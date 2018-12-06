#include "Precompiled.hpp"
#include "FileApi.hpp"
#include <memory>
#include <string>
#include <clocale>
#include <cwchar>
#include <vector>

BOOL HashCalc(std::wstring TargetFile, LPCWSTR lpwAlgToUse, NTSTATUS & status, std::wstring & computedHash ) {
	BCRYPT_ALG_HANDLE       hAlg = NULL;
	BCRYPT_HASH_HANDLE      hHash = NULL;
	DWORD                   cbData = 0,
							cbHashObject = 0;
	PBYTE                   pbHashObject = NULL;
	
	BOOL bSuccessful = FALSE;

	auto targetFile = File(TargetFile);
	BYTE rgbFile[1024];
	DWORD cbRead = 0;
	
	status = STATUS_UNSUCCESSFUL;

	//open an algorithm handle
	status = BCryptOpenAlgorithmProvider(&hAlg, lpwAlgToUse, NULL, 0);

	if (status != STATUS_SUCCESS)
	{
		if (hAlg)
		{
			BCryptCloseAlgorithmProvider(hAlg, 0);
		}
		
		return FALSE;
	}

	//calculate the size of the buffer to hold the hash object
	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
	if (status != STATUS_SUCCESS)
	{
		if (hAlg)
		{
			BCryptCloseAlgorithmProvider(hAlg, 0);
		}

		return FALSE;
	}
	
	std::unique_ptr<BYTE> hashBuffer(new BYTE[cbHashObject]);

	pbHashObject = hashBuffer.get();

	if (NULL == pbHashObject)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);

		return FALSE;
	}

	//calculate the length of the hash
	DWORD cbHash = 0;

	status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&cbHash), sizeof(DWORD), &cbData, 0);
	if (status != STATUS_SUCCESS)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);

		return FALSE;
	}
	std::unique_ptr<BYTE> hashResult(new BYTE[cbHash]);
	
	PBYTE pbHash = hashResult.get();

	if (NULL == pbHash)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
		
		return FALSE;
	}

	//create a hash
	status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
	if (status != STATUS_SUCCESS)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);

		return FALSE;
	}



	do {
		targetFile.ReadFileBuffer(rgbFile, 1024, cbRead);
		if (!cbRead) {
			break;
		}
		//hash some data
		status = BCryptHashData(hHash, (PBYTE)rgbFile, cbRead, 0);
		if (status != STATUS_SUCCESS)
		{
			BCryptCloseAlgorithmProvider(hAlg, 0);

			return FALSE;
		}
	} while (true);

	//close the hash
	status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
	if (status != STATUS_SUCCESS)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);

		if (hHash)
		{
			BCryptDestroyHash(hHash);
		}

		return FALSE;
	}

	BCryptCloseAlgorithmProvider(hAlg, 0);

	BCryptDestroyHash(hHash);

	const char * cs = reinterpret_cast<const char *>(pbHash);

	std::mbstate_t state = std::mbstate_t();

	size_t outSize = 0;

	size_t wstring_size = cbHash + 1;

	std::unique_ptr<wchar_t> wHash(new wchar_t[wstring_size]);

	mbstowcs_s(&outSize, wHash.get(), wstring_size, cs, cbHash);

	computedHash = wHash.get();

	return TRUE;

}
void ConvertWstrToAsciiHexStr(std::wstring wcs, std::string & hashHexValStr) {
	size_t charsConverted = 0;

	size_t outputSize = wcs.length() + 1;

	char outputString[1024];
	char hashHexVal[1024];

	wcstombs_s(&charsConverted, outputString, outputSize, wcs.c_str(), wcs.size());

	for (unsigned int uiIdx = 0; uiIdx < (charsConverted - 1); uiIdx++) {

		unsigned int uiChar = (outputString[uiIdx] & 0xf0) >> 4;

		if (uiChar > 9)
		{
			hashHexVal[uiIdx * 2] = uiChar + 'A' - 10;
		}
		else
		{
			hashHexVal[uiIdx * 2] = uiChar + '0';
		}

		uiChar = (outputString[uiIdx] & 0xf);

		if (uiChar > 9)
		{
			hashHexVal[(uiIdx * 2) + 1] = uiChar + 'A' - 10;
		}
		else
		{
			hashHexVal[(uiIdx * 2) + 1] = uiChar + '0';
		}
	}
	hashHexVal[(charsConverted - 1) * 2] = 0;
	hashHexValStr = hashHexVal;
}