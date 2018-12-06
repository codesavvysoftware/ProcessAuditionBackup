#pragma once
#include "Precompiled.hpp"
#include <memory>
DWORD TestEncrypting();

class BCryption 
{
public:
	BCryption(wstring AlgID);
	~BCryption();


private:
	DWORD GetProperty(BCRYPT_HANDLE handle, LPCWSTR property);

	bool CreateAlgorithmProvider(wstring &);

	DWORD BCryption::GetProperty(BCRYPT_HANDLE handle, LPCWSTR property);
	DWORD BCryption::GetObjectLength();
	DWORD BCryption::GetHashLength();


	BCRYPT_ALG_HANDLE        m_hAlg;
	BCRYPT_HASH_HANDLE       m_hHash;
	LPCWSTR                  m_AlgID;
	LPCWSTR                  m_Implementation;
	std::unique_ptr<UCHAR>   m_HashBfr;


};
