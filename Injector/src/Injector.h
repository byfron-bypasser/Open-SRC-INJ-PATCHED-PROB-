#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "settings.h"

#define DBG(fmt, ...) printf("[Debug - %s] " fmt "\n", Base_Name, ##__VA_ARGS__)
#define ERR(fmt, ...) printf("[Error - %s] " fmt " (gle=%lu)\n", Base_Name, ##__VA_ARGS__, GetLastError())

struct Handle_Deleter
{
    void operator()(HANDLE h) const noexcept;
};

using Unique_Handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, Handle_Deleter>;

struct Map_Result
{
    uintptr_t Image_Base;
    uintptr_t Entry_Point;
};

[[nodiscard]] std::optional<DWORD> Find_Process(std::wstring_view name);
[[nodiscard]] std::optional<uintptr_t> Remote_Module_Base(DWORD pid, std::wstring_view name);
[[nodiscard]] std::optional<std::vector<uint8_t>> Read_File(std::string_view path);
[[nodiscard]] std::optional<std::string> Exe_Dir_Path(std::string_view filename);
[[nodiscard]] std::optional<DWORD> Find_Parked_Thread(DWORD pid);
[[nodiscard]] std::optional<Map_Result> Manual_Map(HANDLE proc, const std::vector<uint8_t>& raw);
[[nodiscard]] std::optional<uintptr_t> Stomp_And_Hijack(
    HANDLE proc,
    DWORD pid,
    DWORD tid,
    std::wstring_view dll_name,
    uintptr_t image_base,
    uintptr_t dllmain_va);