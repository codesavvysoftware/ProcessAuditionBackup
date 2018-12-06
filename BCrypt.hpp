#pragma once
#include "Precompiled.hpp"
#include <memory>
DWORD TestEncrypting();

class BCryption 
{
public:
	BCryption(wstring AlgID);

private:
	DWORD GetProperty(BCRYPT_HANDLE handle, LPCWSTR property);

	void CreateAlgorithmProvider();

	void CloseAlgorithmProvider();

	BCRYPT_ALG_HANDLE        m_hAlg;
	BCRYPT_HASH_HANDLE       m_hHash;
	wstring                  m_AlgID;
	LPCWSTR                  m_Implementation;
	std::unique_ptr<UCHAR>   m_HashBfr;


};
class BCryptAlgorithmProvider
{
  public:
    BCryptAlgorithmProvider();
    DWORD GetObjectLength();
    DWORD GetHashLength();
    ~BCryptAlgorithmProvider();
    operator BCRYPT_ALG_HANDLE() const { return m_handle; }

  private:
    BCRYPT_ALG_HANDLE m_handle = NULL;
	BCRYPT_ALG_HANDLE BCryptOpenAlgorithmProvider_(LPCWSTR algorithmId_, LPCWSTR implementation);
	void BCryptCloseAlgorithmProvider_(BCRYPT_ALG_HANDLE algorithmHandle);
	template<typename T>
	T BCryptGetProperty_(BCRYPT_HANDLE handle, LPCWSTR property);

};

class BCryptHashEngine
{
  public:
    BCryptHashEngine(BCryptAlgorithmProvider &);
    void             Update(PUCHAR, ULONG);
    std::vector<int> Finish();
    ~BCryptHashEngine();

  private:
    BCryptAlgorithmProvider  &   m_provider;
    BCRYPT_HASH_HANDLE           m_handle;
	std::unique_ptr<UCHAR>       m_hashBuffer;

	BCRYPT_HASH_HANDLE
		BCryptCreateHash_(BCRYPT_ALG_HANDLE algorithmHandle, PUCHAR hashObjectBuffer, DWORD hashObjectSizeInBytes);
	    std::vector<int> BCryptFinishHash_(BCryptAlgorithmProvider provider, BCRYPT_HASH_HANDLE hashHandle);
		void BCryptDestroyHash_(BCRYPT_HASH_HANDLE hashHandle);

};
