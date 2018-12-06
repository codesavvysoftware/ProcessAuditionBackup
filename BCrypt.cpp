/*
 * Helpers around WinAPI's BCrypt (Previously known as BestCrypt, **not** Blowfish Crypt) to make them more C++
 * Friendly.
 */

/* https://docs.microsoft.com/en-us/windows/desktop/SecCNG/cng-portal */

// clang-format off
 #include "Precompiled.hpp"
 #include "WinBase.hpp"
 #include "Memory.hpp"
 #include "FileApi.hpp"
 #include "BCrypt.hpp"
#include <memory>
#include <Wincrypt.h>

// clang-format on

using namespace std;

BCryption::BCryption(wstring AlgID) : m_hAlg(NULL),
                                      m_hHash(NULL),
                                      m_AlgID(AlgID),
                                      m_Implementation(nullptr)
{
}

BCryption::~BCryption()
{
	if (NULL != m_hAlg) {
		NTSTATUS result = BCryptCloseAlgorithmProvider(m_hAlg, 0);
	}
}

void BCryption::CreateAlgorithmProvider()
{
    BCRYPT_ALG_HANDLE handle;
    unsigned long     flags = 0;

    NTSTATUS result = BCryptOpenAlgorithmProvider(&handle, m_AlgID, m_Implementation, flags);

    switch (result) {
        case STATUS_SUCCESS: // The function was successful.
            m_hAlg = handle;
            break;
        case STATUS_NOT_FOUND: // No provider was found for the specified algorithm ID.
            throw runtime_error("Unable to find Algorithm Provider");
            break;
        case STATUS_INVALID_PARAMETER: // One or more parameters are not valid.
        case STATUS_NO_MEMORY:         // A memory allocation failure occurred.
        default:                       // other return codes are possible
            // throw runtime_error(GetLastErrorMessage());
            throw runtime_error("Error!");
            break;
    }
}



DWORD BCryption::GetProperty(BCRYPT_HANDLE handle, LPCWSTR property)
{
    DWORD    output     = 0;
    ULONG    outputSize = sizeof(DWORD);
    ULONG    resultSize = 0;
    ULONG    flags      = 0; // No flags are defined for this function.
    NTSTATUS result     = BCryptGetProperty(handle, property, reinterpret_cast<PUCHAR>(&output), outputSize, &resultSize, flags);

    switch (result) {
        case STATUS_SUCCESS: // The function was successful.
            return output;

        case STATUS_BUFFER_TOO_SMALL: // The buffer size specified by the cbOutput parameter is not large enough to hold
            // the property value.
            throw runtime_error("Provided Buffer is Too Small.");
            break;

        case STATUS_INVALID_HANDLE: // The handle in the hObject parameter is not valid.
            throw runtime_error("Invalid Handle.");
            break;

        case STATUS_INVALID_PARAMETER: // One or more parameters are not valid.
            throw runtime_error("Invalid Parameter.");
            break;

        case STATUS_NOT_SUPPORTED: // The named property specified by the pszProperty parameter is not supported.
            throw runtime_error("Property is Unsupported.");
            break;

        default:
            // throw runtime_error(GetLastErrorMessage());
            throw runtime_error("Error!");
            break;
    }
}

void BCryption::CloseAlgorithmProvider()
{
    ULONG    flags  = 0; // No flags are defined for this function.
    NTSTATUS result = BCryptCloseAlgorithmProvider(m_hAlg, flags);
    switch (result) {
        case STATUS_SUCCESS: // The function was successful.
            return;
            break;
        case STATUS_INVALID_HANDLE: // The algorithm handle in the hAlgorithm parameter is not valid.
            throw runtime_error("Invalid Handle.");
            break;
        default: // other return codes are possible
            // throw runtime_error(GetLastErrorMessage());
            throw runtime_error("Error!");
            break;
    }
}

BCryptAlgorithmProvider::BCryptAlgorithmProvider()
{
    auto algorithmId_   = (LPCWSTR)BCRYPT_SHA256_ALGORITHM;
    auto implementation = (LPCWSTR)NULL; // NULL => the default provider for the specified algorithm will be loaded.
    auto flags          = (ULONG)0;
    m_handle            = BCryptOpenAlgorithmProvider_(algorithmId_, implementation);
}

DWORD BCryptAlgorithmProvider::GetObjectLength() { 
	return BCryptGetProperty_<DWORD>(m_handle, BCRYPT_OBJECT_LENGTH); 
}
DWORD BCryptAlgorithmProvider::GetHashLength() { 
	return BCryptGetProperty_<DWORD>(m_handle, BCRYPT_HASH_LENGTH); 
}

BCryptAlgorithmProvider::~BCryptAlgorithmProvider()
{
    if (NULL != m_handle) {
        BCryptCloseAlgorithmProvider_(m_handle);
    }
}

BCRYPT_HASH_HANDLE
BCryptHashEngine::BCryptCreateHash_(BCRYPT_ALG_HANDLE algorithmHandle, PUCHAR hashObjectBuffer, DWORD hashObjectSizeInBytes)
{
    auto hashHandle        = (BCRYPT_HASH_HANDLE)NULL;
    auto secretBuffer      = (PUCHAR)NULL;
    auto secretSizeInBytes = (ULONG)0;
    auto flags             = (ULONG)0;
    auto result            = BCryptCreateHash(
        algorithmHandle, &hashHandle, hashObjectBuffer, hashObjectSizeInBytes, secretBuffer, secretSizeInBytes, flags);
    switch (result) {
        case STATUS_SUCCESS: // The function was successful.
            return hashHandle;
            break;

        case STATUS_BUFFER_TOO_SMALL: // The size of the hash object specified by the hashObjectSizeInBytes parameter is
                                      // not large enough to hold the hash object.
            throw runtime_error("Hash Buffer SizeInBytes is Too Small.");
            break;

        case STATUS_INVALID_HANDLE: // The algorithm handle in the algorithmHandle parameter is not valid.
            throw runtime_error("Invalid Algorithm Handle.");
            break;

        case STATUS_NOT_SUPPORTED: // The algorithm provider specified by the algorithmHandle parameter does not support
                                   // the hash interface.
            throw runtime_error("Algorithm does not Support the Hash Interface.");
            break;

        case STATUS_INVALID_PARAMETER: // One or more parameters are not valid.
            throw runtime_error("Invalid Parameter.");
            break;
    }
}

void BCryptHashData_(BCRYPT_HASH_HANDLE hashHandle, PUCHAR dataBuffer, ULONG dataSizeInBytes)
{
    auto flags  = (ULONG)0; // No flags are currently defined, so this parameter should be zero.
    auto result = BCryptHashData(hashHandle, dataBuffer, dataSizeInBytes, flags);
    switch (result) {
        case STATUS_SUCCESS: // The function was successful.
            return;
            break;

        case STATUS_INVALID_PARAMETER: // One or more parameters are not valid.
            throw runtime_error("Invalid Parameter.");
            break;

        case STATUS_INVALID_HANDLE: // The hash handle in the hHash parameter is not valid. After the BCryptFinishHash
                                    // function has been called for a hash handle, that handle cannot be reused.
            throw runtime_error("Invalid Hash Handle.");
            break;
        default: // other return codes are possible
            // throw runtime_error(GetLastErrorMessage());
            throw runtime_error("Error!");
            break;
    }
}

vector<int> BCryptHashEngine::BCryptFinishHash_(BCryptAlgorithmProvider provider, BCRYPT_HASH_HANDLE hashHandle)
{
    vector<int> hashVector;

    auto hashSizeInBytes = provider.GetHashLength();
	
	unique_ptr<UCHAR> hashBuffer(new UCHAR[hashSizeInBytes]);

	PUCHAR puc = hashBuffer.get();

	auto flags           = (ULONG)0;
    auto result          = BCryptFinishHash(hashHandle, puc, hashSizeInBytes, flags);
    if (STATUS_SUCCESS == result) { // The function was successful.
        for (DWORD n = 0; n < hashSizeInBytes; n++) { 

			hashVector.push_back(static_cast<int>(puc[n])); 
		}
        return hashVector;
    }
    switch (result) {
        case STATUS_INVALID_HANDLE: // The hash handle in the hHash parameter is not valid. After the BCryptFinishHash
                                    // function has been called for a hash handle, that handle cannot be reused.
            throw runtime_error("Invalid Handle.");
            break;

        case STATUS_INVALID_PARAMETER: // One or more parameters are not valid. This includes the case where cbOutput is
                                       // not the same size as the hash.
            throw runtime_error("Invalid Parameter.");
            break;

        default: // other return codes are possible
            // throw runtime_error(GetLastErrorMessage());
            throw runtime_error("Error!");
            break;
    }
}

void BCryptHashEngine::BCryptDestroyHash_(BCRYPT_HASH_HANDLE hashHandle)
{
    auto result = BCryptDestroyHash(hashHandle);
    switch (result) {
        case STATUS_SUCCESS: // The function was successful.
            return;
            break;

        case STATUS_INVALID_HANDLE: // The algorithm handle in the hHash parameter is not valid.
            throw runtime_error("Invalid Handle.");
            break;

        default: // other return codes are possible
            // throw runtime_error(GetLastErrorMessage());
            throw runtime_error("Error!");
            break;
    }
}

BCryptHashEngine::BCryptHashEngine(BCryptAlgorithmProvider &  p) : m_provider(p)
{
    auto hashObjectSizeInBytes = m_provider.GetObjectLength();

	m_hashBuffer.reset(new UCHAR[hashObjectSizeInBytes]);

    m_handle = BCryptCreateHash_(m_provider, m_hashBuffer.get(), hashObjectSizeInBytes);
}

void BCryptHashEngine::Update(PUCHAR buffer, ULONG sizeInBytes) { BCryptHashData_(m_handle, buffer, sizeInBytes); }

vector<int> BCryptHashEngine::Finish() { 
	return BCryptFinishHash_(m_provider, m_handle); 
}

BCryptHashEngine::~BCryptHashEngine() { 
	BCryptDestroyHash_(m_handle); 
}

#define BUFSIZE 1024
#define MD5LEN  16



DWORD TestEncrypting()
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[BUFSIZE];
	DWORD cbRead = 0;
	BYTE rgbHash[MD5LEN];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	LPCWSTR filename = L"filename.txt";
	// Logic to check usage goes here.

	hFile = CreateFile(filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		printf("Error opening file %s\nError: %d\n", filename,
			dwStatus);
		return dwStatus;
	}

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		printf("MD5 hash of file %s is: ", filename);
		for (DWORD i = 0; i < cbHash; i++)
		{
			printf("%c%c", rgbDigits[rgbHash[i] >> 4],
				rgbDigits[rgbHash[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return dwStatus;
}
