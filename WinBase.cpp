// clang-format off
#include "Precompiled.hpp"
#include "WinBase.hpp"
// clang-format on

using namespace std;

wstring GetErrorMessage(DWORD dwErrorCode)
{
	LPWSTR psz{ nullptr };
	const DWORD cchMsg = 
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		               NULL, // (not used with FORMAT_MESSAGE_FROM_SYSTEM)
		               dwErrorCode,
		               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		               reinterpret_cast<LPWSTR>(&psz),
		               0,
		               NULL);
	if (cchMsg > 0)
	{
		// Assign buffer to smart pointer with custom deleter so that memory gets released
		// in case String's c'tor throws an exception.
		auto deleter = [](void* p) { ::HeapFree(::GetProcessHeap(), 0, p); };
		std::unique_ptr<TCHAR, decltype(deleter)> ptrBuffer(psz, deleter);
		return wstring(ptrBuffer.get(), cchMsg);
	}
	else
	{
		auto error_code{ ::GetLastError() };
		throw std::system_error(error_code, std::system_category(),
			"Failed to retrieve error message string.");
	}
}
/*string GetLastErrorMessage()
{
    /* https://stackoverflow.com/a/45565001 */

/*    LPSTR errorMessageBuffer{nullptr};

    const DWORD   dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER;
    const LPCVOID lpSource     = NULL; // (not used with FORMAT_MESSAGE_FROM_SYSTEM) DWORD
    const DWORD   dwMessageId  = ::GetLastError();
    const DWORD   dwLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    const LPSTR   lpBuffer     = reinterpret_cast<LPSTR>(&errorMessageBuffer);
    const DWORD   nSize        = 0;
    va_list *     Arguments    = NULL;

    const DWORD result = FormatMessageA(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
    if (0 == result) {
        auto errorCode{::GetLastError()};
        throw system_error(errorCode, system_category(), "Failed to retrieve error message string.");

    } else {
        stringstream errorCodeStream;
        errorCodeStream << setfill('0') << setw(8) << hex << dwMessageId;
        string errorCode = errorCodeStream.str();

        // Assign buffer to smart pointer with custom deleter so that memory gets
        // released in case string's c'tor throws an exception.
        auto deleter = [](void * p) { ::HeapFree(::GetProcessHeap(), 0, p); };

        unique_ptr<CHAR, decltype(deleter)> bufferPointer(errorMessageBuffer, deleter);

        string errorMessage = string(bufferPointer.get(), result);
        errorMessage.resize(errorMessage.find_last_not_of("\n"));
        errorMessage.resize(errorMessage.find_last_not_of(".") + 1);

        return "0x" + errorCode + "::" + errorMessage;
    }
}*/

// ToDo: QueryFullProcessImageNameW function
// ToDo: GetModuleFileName function :: Retrieves the fully qualified path for the file that contains the specified
// module.
// ToDo: GetModuleFileNameEx function :: Retrieves the fully qualified path for the file containing the specified
// module.

// To retrieve the name of the main executable module for a remote process, use the GetProcessImageFileName or
// QueryFullProcessImageName function. This is more efficient and more reliable than calling the GetModuleFileNameEx
// function with a NULL module handle.
