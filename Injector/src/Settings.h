#pragma once

extern const char* Module_Name;
extern const char* Base_Name;

constexpr std::wstring_view Injector_Target = L"RobloxPlayerBeta.exe";
constexpr std::array<std::wstring_view, 2> Modules_Available{ L"advapi32.dll", L"combase.dll" };