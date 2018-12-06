#include "stdafx.h"
#include "CppUnitTest.h"
#include "../ProcessAuditingDefs.hpp"
#include "../JsonInputProcessing.hpp"
#include <locale>
#include <codecvt>
#include <string>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ProcessingAuditingUtest
{		
	TEST_CLASS(JsonInputProcessingTests)
	{
	public:
		TEST_CLASS_INITIALIZE(ClassInitialize)
		{
			Logger::WriteMessage(L"Initializing the class");
		}
        
		TEST_METHOD(TestValidRules_6_Ids)
		{
			string jsonOut        = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";
			
			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestValidRules_5_Ids)
		{
			string jsonOut =        R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestValidRules_4_Ids)
		{
			string jsonOut = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestValidRules_3_Ids)
		{
			string jsonOut        = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]}]})";
			
			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);

		}

		TEST_METHOD(TestValidRules_2_Ids)
		{
			string jsonOut        = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]}]})";
			
			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);

		}
		TEST_METHOD(TestValidRules_1_Id)
		{
			string jsonOut        = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestValidRules_0_Ids)
		{
			string jsonOut        = R"({"command":"put rules","content":[]})";

			string outputExpected = R"({"command":"put rules","content":[]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestInvalidRules_InvalidPutCommand)
		{
			string jsonOut           = R"({"command":"put xules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected    = R"({"command":"put xules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}],"errors":["unknown command"]})";

			string outputDequeued;
			
			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestInvalidRules_InvalidContentDeclaration)
		{
			string jsonOut           = R"({"command":"put rules","junk":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected    = R"({"command":"put rules","errors":["missing content"],"junk":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);
			
			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestInvalidRules_InvalidIdentificationDeclaration)
		{
			string jsonOut           = R"({"command":"put rules","content":[{"idenn":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identificaion":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"idenn":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}],"errors":["parsing content","[json.exception.out_of_range.403] key 'identification' not found"]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestInvalidRules_InvalidIdentNum)
		{
			string jsonOut = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"Ax","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"Ax","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestInvalidRules_InvalidSpecDecl)
		{
			string jsonOut = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","xpecs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","xpecs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}],"errors":["parsing content","[json.exception.out_of_range.403] key 'specs' not found"]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestInvalidRules_InvalidFileName)
		{
			string jsonOut = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"ilename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"ilename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}

		TEST_METHOD(TestForGarbageInput)
		{
			string jsonOut = R"({"crap":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"ilename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"ilename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"ilename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"ilename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}],"crap":"put rules","errors":["missing command"]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}

		TEST_METHOD(TestPing)
		{
			string jsonOut = R"({"command":"ping"})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"ping","response":"pong"})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
		TEST_METHOD(TestQuit)
		{
			string jsonOut = R"({"command":"quit"})";

			string outputNotExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"}]},{"identification":"1","specs":[{"filename":"reg.exe"}]},{"identification":"2","specs":[{"filename":"vssadmin.exe"}]},{"identification":"3","specs":[{"filename":"ntdsutil.exe"}]},{"identification":"4","specs":[{"filename":"regsvr32.exe"}]},{"identification":"5","specs":[{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"quit","response":"acknowledged"})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued, true);

			Assert::AreNotEqual(outputNotExpected, outputDequeued, false);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}

		TEST_METHOD(TestValidRules_SpecVector)
		{
		    string jsonOut = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"},{"filename":"reg.exe"},{"filename":"vssadmin.exe"},{"filename":"ntdsutil.exe"},{"filename":"regsvr32.exe"},{"filename":"mshta.exe"}]}]})";

			string outputExpected = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"},{"filename":"reg.exe"},{"filename":"vssadmin.exe"},{"filename":"ntdsutil.exe"},{"filename":"regsvr32.exe"},{"filename":"mshta.exe"}]}]})";

			string outputDequeued;

			ExecuteJsonInputTest(jsonOut, outputDequeued);

			Assert::AreEqual(outputExpected, outputDequeued, false);
		}
	private:
		wstring ConvertNarrowToWideString(string narrowStr) {
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			//		std::string narrow = converter.to_bytes(wide_utf16_source_string);
			return converter.from_bytes(narrowStr);
		}

		void ExecuteJsonInputTest(string jsonOut, string & processedJson, BOOL bExpectQuitIndicated = FALSE) {
			JsonInputProcessing jip;

			auto jsonBuffer = json::parse(jsonOut);

			BOOL bQuitIndicated = FALSE;

			AtomicBool ceaseRequested(false);

			JsonQueue         outputQueue;
			RuleQueue         incomingRuleQueue;
			jip.ProcessJsonInput(jsonBuffer, outputQueue, incomingRuleQueue, bQuitIndicated);
			json item;

			BOOL itemDequeued = outputQueue.wait_dequeue_timed(item, chrono::milliseconds(1000));

			Assert::IsTrue(itemDequeued);

			Assert::IsTrue((bQuitIndicated == bExpectQuitIndicated));

			processedJson = item.dump();

			Logger::WriteMessage(processedJson.c_str());
		}

	};

}