#pragma once
#include <string>
BOOL HashCalc(std::wstring, LPCWSTR, NTSTATUS &, std::wstring &);
void ConvertWstrToAsciiHexStr(std::wstring wcs, string & hashHexValStr);
