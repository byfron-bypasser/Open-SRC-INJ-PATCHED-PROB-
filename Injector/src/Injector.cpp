#include "injector.h"
#include <cstdio>
#include <fstream>

const char* Module_Name = "Moon.dll";
const char* Base_Name = "Project Moon";


void Handle_Deleter::operator()(HANDLE h) const noexcept
{
    if (h && h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }
}

[[nodiscard]] std::optional<DWORD> Find_Process(std::wstring_view name)
{
    Unique_Handle snap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if (!snap || snap.get() == INVALID_HANDLE_VALUE)
    {
        return std::nullopt;
    }

    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);

    if (!Process32FirstW(snap.get(), &e))
    {
        return std::nullopt;
    }

    do
    {
        if (name == e.szExeFile)
        {
            return e.th32ProcessID;
        }
    } while (Process32NextW(snap.get(), &e));

    return std::nullopt;
}

[[nodiscard]] std::optional<uintptr_t> Remote_Module_Base(DWORD pid, std::wstring_view name)
{
    Unique_Handle snap{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if (!snap || snap.get() == INVALID_HANDLE_VALUE)
    {
        return std::nullopt;
    }

    MODULEENTRY32W e{};
    e.dwSize = sizeof(e);

    if (!Module32FirstW(snap.get(), &e))
    {
        return std::nullopt;
    }

    do
    {
        if (name == e.szModule)
        {
            return reinterpret_cast<uintptr_t>(e.modBaseAddr);
        }
    } while (Module32NextW(snap.get(), &e));

    return std::nullopt;
}

[[nodiscard]] std::optional<std::vector<uint8_t>> Read_File(std::string_view path)
{
    std::ifstream f(path.data(), std::ios::binary | std::ios::ate);
    if (!f)
    {
        return std::nullopt;
    }

    auto sz = f.tellg();
    if (sz <= 0)
    {
        return std::nullopt;
    }

    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(buf.data()), buf.size());

    return buf;
}

[[nodiscard]] std::optional<std::string> Exe_Dir_Path(std::string_view filename)
{
    char buf[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, buf, MAX_PATH))
    {
        return std::nullopt;
    }

    std::string path(buf);
    auto sep = path.find_last_of("\\/");
    if (sep == std::string::npos)
    {
        return std::nullopt;
    }

    path.resize(sep + 1);
    path += filename;

    return path;
}

[[nodiscard]] std::optional<DWORD> Find_Parked_Thread(DWORD pid)
{
    uintptr_t ntdll_lo = reinterpret_cast<uintptr_t>(GetModuleHandleA("ntdll.dll"));
    if (!ntdll_lo)
    {
        ERR("GetModuleHandleA(ntdll) failed");
        return std::nullopt;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_lo);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(ntdll_lo + dos->e_lfanew);
    uintptr_t ntdll_hi = ntdll_lo + nt->OptionalHeader.SizeOfImage;

    DBG("ntdll range: %llx - %llx", (unsigned long long)ntdll_lo, (unsigned long long)ntdll_hi);

    Unique_Handle snap{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if (!snap || snap.get() == INVALID_HANDLE_VALUE)
    {
        ERR("TH32CS_SNAPTHREAD failed");
        return std::nullopt;
    }

    THREADENTRY32 e{};
    e.dwSize = sizeof(e);

    if (!Thread32First(snap.get(), &e))
    {
        return std::nullopt;
    }

    int total = 0, opened = 0, suspended = 0;

    do
    {
        if (e.th32OwnerProcessID != pid)
        {
            continue;
        }

        ++total;

        Unique_Handle thr{ OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, e.th32ThreadID) };
        if (!thr)
        {
            DBG(" tid %lu OpenThread failed gle=%lu", e.th32ThreadID, GetLastError());
            continue;
        }

        ++opened;

        if (SuspendThread(thr.get()) == static_cast<DWORD>(-1))
        {
            DBG(" tid %lu SuspendThread failed gle=%lu", e.th32ThreadID, GetLastError());
            continue;
        }

        ++suspended;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        bool parked = false;

        if (GetThreadContext(thr.get(), &ctx))
        {
            parked = ctx.Rip >= ntdll_lo && ctx.Rip < ntdll_hi;
            DBG(" tid %lu rip=%llx parked=%d", e.th32ThreadID, (unsigned long long)ctx.Rip, (int)parked);
        }
        else
        {
            DBG(" tid %lu GetThreadContext failed gle=%lu", e.th32ThreadID, GetLastError());
        }

        ResumeThread(thr.get());

        if (parked)
        {
            DBG("selected parked tid %lu", e.th32ThreadID);
            return e.th32ThreadID;
        }
    } while (Thread32Next(snap.get(), &e));

    DBG("find_parked_thread: total=%d opened=%d suspended=%d — none parked in ntdll", total, opened, suspended);
    return std::nullopt;
}

[[nodiscard]] std::optional<Map_Result> Manual_Map(HANDLE proc, const std::vector<uint8_t>& raw)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return std::nullopt;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return std::nullopt;
    }

    const auto& opt = nt->OptionalHeader;
    SIZE_T img_size = opt.SizeOfImage;

    DBG("manual_map: allocating %zu bytes (ImageSize)", img_size);

    auto* alloc = static_cast<uint8_t*>(
        VirtualAllocEx(proc, reinterpret_cast<LPVOID>(opt.ImageBase), img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!alloc)
    {
        alloc = static_cast<uint8_t*>(
            VirtualAllocEx(proc, nullptr, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    }

    if (!alloc)
    {
        ERR("VirtualAllocEx failed");
        return std::nullopt;
    }

    uintptr_t base = reinterpret_cast<uintptr_t>(alloc);
    DBG("manual_map: allocated base %llx", (unsigned long long)base);

    int64_t delta = static_cast<int64_t>(base) - static_cast<int64_t>(opt.ImageBase);

    WriteProcessMemory(proc, alloc, raw.data(), opt.SizeOfHeaders, nullptr);

    const auto* secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = secs[i];
        if (s.SizeOfRawData)
        {
            WriteProcessMemory(proc, alloc + s.VirtualAddress, raw.data() + s.PointerToRawData, s.SizeOfRawData, nullptr);
        }
    }

    const auto& reloc_dd = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dd.VirtualAddress && delta != 0)
    {
        auto* blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(raw.data() + reloc_dd.VirtualAddress);
        const auto* end = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<const uint8_t*>(blk) + reloc_dd.Size);

        while (blk < end && blk->SizeOfBlock)
        {
            DWORD count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* entries = reinterpret_cast<const WORD*>(blk + 1);

            for (DWORD j = 0; j < count; ++j)
            {
                if ((entries[j] >> 12) != IMAGE_REL_BASED_DIR64)
                {
                    continue;
                }

                uintptr_t va = base + blk->VirtualAddress + (entries[j] & 0xFFF);
                uintptr_t val{};
                ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(va), &val, sizeof(val), nullptr);
                val += static_cast<uintptr_t>(delta);
                WriteProcessMemory(proc, reinterpret_cast<LPVOID>(va), &val, sizeof(val), nullptr);
            }

            blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<const uint8_t*>(blk) + blk->SizeOfBlock);
        }
    }

    const auto& imp_dd = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dd.VirtualAddress && imp_dd.VirtualAddress < raw.size())
    {
        auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(raw.data() + imp_dd.VirtualAddress);
        const auto* raw_end = raw.data() + raw.size();

        while (reinterpret_cast<const uint8_t*>(desc) + sizeof(*desc) <= raw_end && desc->Name)
        {
            if (desc->Name >= raw.size())
            {
                ++desc;
                continue;
            }

            const char* dll_name = reinterpret_cast<const char*>(raw.data() + desc->Name);
            HMODULE mod = LoadLibraryA(dll_name);

            const DWORD int_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            if (!int_rva || int_rva >= raw.size())
            {
                ++desc;
                continue;
            }

            auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(raw.data() + int_rva);
            uintptr_t iat_va = base + desc->FirstThunk;

            for (SIZE_T k = 0; ; ++k)
            {
                const auto* entry = &thunk[k];
                if (reinterpret_cast<const uint8_t*>(entry) + sizeof(*entry) > raw_end)
                {
                    break;
                }
                if (!entry->u1.AddressOfData)
                {
                    break;
                }

                uintptr_t fn{};
                if (entry->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    fn = reinterpret_cast<uintptr_t>(GetProcAddress(mod, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(entry->u1.Ordinal))));
                }
                else
                {
                    DWORD ibn_rva = static_cast<DWORD>(entry->u1.AddressOfData);
                    if (ibn_rva < raw.size())
                    {
                        auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(raw.data() + ibn_rva);
                        fn = reinterpret_cast<uintptr_t>(GetProcAddress(mod, ibn->Name));
                    }
                }

                WriteProcessMemory(proc, reinterpret_cast<LPVOID>(iat_va + k * sizeof(uintptr_t)), &fn, sizeof(fn), nullptr);
            }
            ++desc;
        }
    }

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = secs[i];
        if (!s.SizeOfRawData && !s.Misc.VirtualSize)
        {
            continue;
        }

        DWORD prot{};
        bool exec = !!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE);
        bool read = !!(s.Characteristics & IMAGE_SCN_MEM_READ);
        bool writ = !!(s.Characteristics & IMAGE_SCN_MEM_WRITE);

        if (exec && writ)      prot = PAGE_EXECUTE_READWRITE;
        else if (exec && read) prot = PAGE_EXECUTE_READ;
        else if (exec)         prot = PAGE_EXECUTE;
        else if (writ)         prot = PAGE_READWRITE;
        else if (read)         prot = PAGE_READONLY;
        else                   prot = PAGE_NOACCESS;

        DWORD old{};
        SIZE_T sz = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        VirtualProtectEx(proc, alloc + s.VirtualAddress, sz, prot, &old);
    }

    return Map_Result{ base, base + opt.AddressOfEntryPoint };
}

[[nodiscard]] std::optional<uintptr_t> Stomp_And_Hijack(
    HANDLE proc,
    DWORD pid,
    DWORD tid,
    std::wstring_view dll_name,
    uintptr_t image_base,
    uintptr_t dllmain_va)
{
    auto dll_base_opt = Remote_Module_Base(pid, dll_name);
    if (!dll_base_opt)
    {
        DBG("stomp: module not found");
        return std::nullopt;
    }

    uintptr_t dll_base = *dll_base_opt;
    DBG("stomp: %.*ls base=%llx", (int)dll_name.size(), dll_name.data(), (unsigned long long)dll_base);

    IMAGE_DOS_HEADER dos{};
    ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(dll_base), &dos, sizeof(dos), nullptr);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        DBG("stomp: bad DOS magic");
        return std::nullopt;
    }

    IMAGE_NT_HEADERS64 nt{};
    ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(dll_base + dos.e_lfanew), &nt, sizeof(nt), nullptr);

    uintptr_t shbase = dll_base + dos.e_lfanew
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt.FileHeader.SizeOfOptionalHeader;

    constexpr DWORD kPageSz = 0x1000;
    constexpr SIZE_T kMinNeeded = 256;

    uintptr_t tail_va = 0;
    DWORD tail_size = 0;

    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER sec{};
        ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(shbase + i * sizeof(IMAGE_SECTION_HEADER)), &sec, sizeof(sec), nullptr);

        if (!(sec.Characteristics & IMAGE_SCN_CNT_CODE))
        {
            continue;
        }

        DWORD aligned = (sec.Misc.VirtualSize + kPageSz - 1) & ~(kPageSz - 1);
        DWORD tail = aligned - sec.Misc.VirtualSize;

        char sname[9]{};
        memcpy(sname, sec.Name, 8);

        DBG("stomp: section '%s' vsz=%lu page_tail=%lu", sname, sec.Misc.VirtualSize, tail);

        if (tail >= kMinNeeded)
        {
            tail_va = dll_base + sec.VirtualAddress + sec.Misc.VirtualSize;
            tail_size = tail;
            DBG("stomp: selected tail at %llx (%lu bytes)", (unsigned long long)tail_va, tail_size);
            break;
        }
    }

    if (!tail_va)
    {
        DBG("stomp: no code section with sufficient page tail");
        return std::nullopt;
    }

    Unique_Handle thr{ OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid) };
    if (!thr)
    {
        ERR("stomp_hijack: OpenThread tid=%lu failed", tid);
        return std::nullopt;
    }

    if (SuspendThread(thr.get()) == static_cast<DWORD>(-1))
    {
        ERR("stomp_hijack: SuspendThread failed");
        return std::nullopt;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(thr.get(), &ctx))
    {
        ERR("stomp_hijack: GetThreadContext failed");
        ResumeThread(thr.get());
        return std::nullopt;
    }

    uintptr_t orig_rip = ctx.Rip;
    DBG("stomp_hijack: tid=%lu orig_rip=%llx", tid, (unsigned long long)orig_rip);

    uintptr_t rsp_slot = tail_va + tail_size - 8;
    std::vector<uint8_t> sc(tail_size, 0);
    SIZE_T n = 0;

    auto e8 = [&](uint8_t v) { sc[n++] = v; };
    auto e32 = [&](uint32_t v) { for (int b = 0; b < 4; ++b) sc[n++] = static_cast<uint8_t>(v >> (b * 8)); };
    auto e64 = [&](uint64_t v) { for (int b = 0; b < 8; ++b) sc[n++] = static_cast<uint8_t>(v >> (b * 8)); };

    e8(0x9C);
    e8(0x50); e8(0x51); e8(0x52); e8(0x53);
    e8(0x55); e8(0x56); e8(0x57);
    for (int r = 0; r < 8; ++r)
    {
        e8(0x41);
        e8(0x50 + r);
    }

    e8(0x48); e8(0xB8); e64(rsp_slot);
    e8(0x48); e8(0x89); e8(0x20);
    e8(0x48); e8(0x83); e8(0xE4); e8(0xF0);
    e8(0x48); e8(0x83); e8(0xEC); e8(0x20);
    e8(0x48); e8(0xB9); e64(image_base);
    e8(0x48); e8(0xBA); e64(1ULL);
    e8(0x45); e8(0x33); e8(0xC0);
    e8(0x48); e8(0xB8); e64(dllmain_va);
    e8(0xFF); e8(0xD0);
    e8(0x48); e8(0x83); e8(0xC4); e8(0x20);
    e8(0x48); e8(0xB8); e64(rsp_slot);
    e8(0x48); e8(0x8B); e8(0x20);

    for (int r = 7; r >= 0; --r)
    {
        e8(0x41);
        e8(0x58 + r);
    }

    e8(0x5F); e8(0x5E); e8(0x5D); e8(0x5B);
    e8(0x5A); e8(0x59); e8(0x58);
    e8(0x9D);

    e8(0x68); e32(static_cast<uint32_t>(orig_rip));
    e8(0xC7); e8(0x44); e8(0x24); e8(0x04);
    e32(static_cast<uint32_t>(orig_rip >> 32));
    e8(0xC3);

    DBG("stomp_hijack: shellcode %zu bytes, rsp_slot=%llx", n, (unsigned long long)rsp_slot);

    DWORD old{};
    if (!VirtualProtectEx(proc, reinterpret_cast<LPVOID>(tail_va), tail_size, PAGE_EXECUTE_READWRITE, &old))
    {
        ERR("stomp_hijack: VirtualProtectEx RWX failed");
        ResumeThread(thr.get());
        return std::nullopt;
    }

    bool wpm_ok = !!WriteProcessMemory(proc, reinterpret_cast<LPVOID>(tail_va), sc.data(), tail_size, nullptr);
    VirtualProtectEx(proc, reinterpret_cast<LPVOID>(tail_va), tail_size, PAGE_EXECUTE_READ, &old);

    if (!wpm_ok)
    {
        ERR("stomp_hijack: WriteProcessMemory failed");
        ResumeThread(thr.get());
        return std::nullopt;
    }

    FlushInstructionCache(proc, reinterpret_cast<LPVOID>(tail_va), tail_size);

    ctx.Rip = static_cast<DWORD64>(tail_va);
    if (!SetThreadContext(thr.get(), &ctx))
    {
        ERR("stomp_hijack: SetThreadContext failed");
        ResumeThread(thr.get());
        return std::nullopt;
    }

    ResumeThread(thr.get());
    DBG("stomp_hijack: thread redirected to %llx inside %.*ls", (unsigned long long)tail_va, (int)dll_name.size(), dll_name.data());

    return tail_va;
}