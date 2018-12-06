#pragma once
#ifndef FILEAPI_HPP
#define FILEAPI_HPP
#include "Precompiled.hpp"

    std::vector<std::wstring>
    GetLogicalDriveStringsW_(void);

std::vector<std::wstring> QueryDosDeviceW_(void);
std::vector<std::wstring> QueryDosDeviceW_(const std::wstring &);

std::wstring MapWin32FileName(const std::wstring &);

class File
{
  public:
    File(std::wstring fileName);

	void ReadFileBuffer(BYTE * rgbFile, DWORD bufSize, DWORD & numRead);

	BOOL  UtestMethod(DWORD dw) {
		BOOL bRetval = FALSE;

		if (dw == 5)
		{
			bRetval = TRUE;
		}

		return bRetval;
	}

    operator HANDLE() const { return m_Handle; }

    ~File();

  private:
    HANDLE  m_Handle;
    LPCWSTR m_FileName;
};
#endif // FILEAPI_HPP
