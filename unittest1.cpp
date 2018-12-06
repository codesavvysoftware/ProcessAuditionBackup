#include "stdafx.h"
#include "CppUnitTest.h"
#include "../PsApi.hpp"
#include "../FileApi.hpp"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UTestProcessAuditing
{		
	TEST_CLASS(UnitTest1)
	{
	public:
		
		TEST_METHOD(TestMethod1)
		{
			HANDLE h;
			GetModuleName(h);
			std::wstring ws;
			auto targetFile = File(ws);

			BOOL bResult = targetFile.UtestMethod(3);

			Assert::AreEqual(bResult, TRUE);



		}

	};
}