#pragma once
#ifndef PSAPI_HPP
#    define PSAPI_HPP
#    include "Precompiled.hpp"

std::wstring GetProcessImageFileNameW_(HANDLE);

std::wstring GetModuleBaseNameW_(HANDLE, HMODULE);

std::wstring GetModuleName(HANDLE);

#endif // PSAPI_HPP
