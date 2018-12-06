#include "stdafx.h"
#include "CppUnitTest.h"
#include "../ProcessAuditingDefs.hpp"
//#include "../FileHashCalculation.hpp"
#include <locale>
#include <codecvt>
#include <string>
#include "../HashCalc.hpp"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ProcessingAuditingUtest
{
	TEST_CLASS(GeneratingFileHashTests)
	{
	public:
		TEST_CLASS_INITIALIZE(ClassInitialize)
		{
			Logger::WriteMessage(L"Initializing the GeneratingFileHashTests class");
		}

		TEST_METHOD(GenerateAndCheckKnownHash)
		{
			WStringQueue      hashingRequests;

			wstring FilePath = L"Z:\\ProcessAuditing\\filename.txt";

			Logger::WriteMessage(FilePath.c_str());

			ProcessHashQueue resultQueue;

			NTSTATUS status;

			std::wstring hashProduced;
			
			HashCalc(FilePath, BCRYPT_SHA256_ALGORITHM, status, hashProduced);

			char hashHexVal[1024];

			ConvertWstrToAsciiHex(hashProduced, hashHexVal);
			
			Logger::WriteMessage(hashHexVal);


            
			//FileHashCalculation  fhc;

            //fhc.CalcFileHash(FilePath, resultQueue);

		}
	private:
		void ConvertWstrToAsciiHex(std::wstring wcs, char hashHexVal[]) {
			size_t charsConverted = 0;

			size_t outputSize = wcs.length() + 1;

			char outputString[1024];

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
		}


	};
}
