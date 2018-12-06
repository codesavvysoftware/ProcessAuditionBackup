/*
 * Helpers around WinAPI's PsApi to make them more C++ Friendly.
 */

// clang-format off
 #include "Precompiled.hpp"
 #include "WinBase.hpp"
 #include "PsApi.hpp"
// clang-format on

using namespace std;

wstring GetProcessImageFileNameW_(HANDLE processHandle)
{
    WCHAR bufferArray[MAX_PATH] = L"";

    DWORD bufferSize = (sizeof(bufferArray) / sizeof(WCHAR));

    DWORD innerResult = GetProcessImageFileNameW(processHandle, bufferArray, bufferSize);
    if (0 == innerResult) {
		throw runtime_error("Error");//GetLastErrorMessage());
    }

    return wstring(bufferArray);
}

wstring GetModuleBaseNameW_(HANDLE processHandle, HMODULE moduleHandle)
{
    WCHAR bufferArray[MAX_PATH] = L"";

    DWORD bufferSize = (sizeof(bufferArray) / sizeof(WCHAR));

    DWORD innerResult = GetModuleBaseNameW(processHandle, moduleHandle, bufferArray, bufferSize);
    if (0 == innerResult) {
		throw runtime_error("Error");//GetLastErrorMessage());
    }

    return wstring(bufferArray);
}

wstring GetModuleName(HANDLE processHandle)
{
    HMODULE moduleHandle;                          // An array that receives the list of module handles.
    DWORD   cbModuleHandle = sizeof(moduleHandle); // The size of the lphModule array, in bytes.
    DWORD   cbModuleHandleNeeded; // The number of bytes required to store all module handles in the lphModule
                                  // array.
    BOOL innerResult = EnumProcessModules(processHandle, &moduleHandle, cbModuleHandle, &cbModuleHandleNeeded);
    if (0 == innerResult) {
		throw runtime_error("Error");//GetLastErrorMessage());
    }

    return GetModuleBaseNameW_(processHandle, moduleHandle);
}
