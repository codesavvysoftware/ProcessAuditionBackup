/*
 * Helpers around WinAPI's FileApi to make them more C++ Friendly.
 */

// clang-format off
#include "Precompiled.hpp"
 #include "WinBase.hpp"
 #include "Memory.hpp"
 #include "FileApi.hpp"
// clang-format on

using namespace std;

vector<wstring> GetLogicalDriveStringsW_(void)
{
    vector<wstring> result;

    DWORD bufferLength     = (MAX_PATH - 1);
    WCHAR buffer[MAX_PATH] = L"";

    DWORD innerResult = GetLogicalDriveStringsW(bufferLength, buffer);
    if (0 == innerResult) {
		throw runtime_error("error");//GetLastErrorMessage());
    }

    for (LPWSTR sp = buffer; *sp; sp += static_cast<DWORD>(lstrlenW(sp)) + 1) {
		result.push_back(wstring(sp)); }

    return result;
}

/*
 *  QueryDosDeviceW:
 *    "If the function succeeds, the return value is the number of WCHARs stored
 *     into the buffer pointed to by lpTargetPath.
 *     If the function fails, the return value is zero. To get extended error
 *     information, call GetLastError.
 *     If the buffer is too small, the function fails and the last error code is ERROR_INSUFFICIENT_BUFFER.
 *    "
 *
 *    Since a list of paths are returned, choosing MAX_PATH may be foolish (a single path of maximum length will fit).
 *    Unfortuntaely I do not have any hard data to make a better guess at the apropriate size.
 *      (For instance, useful data would be: how common is it to have multiple paths assigned to a device?)
 */

vector<wstring> QueryDosDeviceW_()
{
    vector<wstring> result;

    WCHAR buffer[(MAX_PATH * MAX_PATH)] = L"";

    DWORD innerResult = QueryDosDeviceW((LPCWSTR)NULL, buffer, ARRAYSIZE(buffer));
    if (0 == innerResult) {
		throw runtime_error("error");//GetLastErrorMessage());
    }

    for (LPWSTR sp = buffer; *sp; sp += lstrlenW(sp) + 1) { result.push_back(wstring(sp)); }

    return result;
}

vector<wstring> QueryDosDeviceW_(const wstring & deviceName)
{
    vector<wstring> result;

    WCHAR buffer[MAX_PATH] = L"";
    auto  firstPos         = 0;
    auto  finalIndex       = deviceName.find_last_not_of(L"\\");
    auto  length           = (finalIndex + 1);
    auto  _deviceName      = deviceName.substr(firstPos, length);

    DWORD innerResult = QueryDosDeviceW(_deviceName.c_str(), buffer, ARRAYSIZE(buffer));
    if (0 == innerResult) {
		throw runtime_error("Error");//GetLastErrorMessage());
    }

    for (LPWSTR sp = buffer; *sp; sp += lstrlenW(sp) + 1) { result.push_back(wstring(sp)); }

    return result;
}

// Maps a "native" (aka Device-based) File Name to a Win32 (aka DOS) File Name
// Returns the un-mapped file name if it cannot map it.
wstring MapWin32FileName(const wstring & nativeFileName)
{
    // EG: nativeFileName => L"\\Device\\HarddiskVolume2\\Windows\\System32\\sihost.exe"
    auto logicalDriveStrings = GetLogicalDriveStringsW_();
    for (const wstring & d : logicalDriveStrings) {
        // EG: d => L"C:\\"
        auto dosDevicePaths = QueryDosDeviceW_(d);
        for (const wstring & p : dosDevicePaths) {
            // EG: p => L"\\Device\\HarddiskVolume2"
            if (p == nativeFileName.substr(0, p.size())) {
                auto startIndex = (p.length() + 1);
                return d + nativeFileName.substr(startIndex);
            }
        }
    }
    return nativeFileName;
}

File::File( std::wstring fileName ) : m_FileName(fileName.c_str())
{
     m_Handle           = CreateFileW(
        m_FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,  //(DWORD)(FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED),
        NULL);
    if (INVALID_HANDLE_VALUE == m_Handle) {
		throw runtime_error("CreateFile Failed: ");//+GetLastErrorMessage());
    }
}

void File::ReadFileBuffer(BYTE * rgbFile, DWORD bufSize, DWORD & numRead) {

	if (!ReadFile(m_Handle, rgbFile, bufSize, &numRead, NULL))
	{
		throw std::runtime_error("error");
	}
}

File::~File()
{
    auto result = CloseHandle(m_Handle);
    if (0 == result) {
        // ToDo: Log => "CloseHandle for CreateFile Failed: " + GetLastErrorMessage()
    }
}
