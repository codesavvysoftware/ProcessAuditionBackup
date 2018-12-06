#include "JsonInputProcessing.hpp"
#include "WinBase.hpp"
#include "PsApi.hpp"
#include "ThreadBase.hpp"
#include "HashCalc.hpp"
#include "FileApi.hpp"
#include <limits>       // std::numeric_limits

#define TEST_MODE

json GetJsonBfr()
{

#ifdef TEST_MODE
	static std::string rulesDataExmpl00 = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"},{"filename":"reg.exe"},{"filename":"vssadmin.exe"},{"filename":"ntdsutil.exe"},{"filename":"regsvr32.exe"},{"filename":"mshta.exe"}]}]})";
	static std::string invalidJSONCmd = R"({command":"quit"})";
	static std::string quitCmd = R"({"command":"quit"})";
	static std::vector<string *> jsonTestStrs{ &rulesDataExmpl00, &invalidJSONCmd, &quitCmd };

	static std::vector<string *>::iterator itCurrentJsonStrIdx = jsonTestStrs.begin();

	if (itCurrentJsonStrIdx == jsonTestStrs.end())
		itCurrentJsonStrIdx = jsonTestStrs.begin();
	
	std::string rawStringToParse = *(*itCurrentJsonStrIdx++);

	auto returnParsedJSON = json::parse(rawStringToParse.c_str());
	return returnParsedJSON;

#else
	json j;
	
	cin >> j;
	
	return j;
#endif
}

void ProcessInput(AtomicBool & ceaseRequested, JsonQueue & outputQueue, RuleQueue & incomingRuleQueue) {
	JsonInputProcessing jip;

	while (false == ceaseRequested.load()) {			
		
		json testJsonBuffer;
		try {
			testJsonBuffer = GetJsonBfr();
		}
		catch (...)
		{
			json jsonBuffer({ {"errors", {"unparsable json input"}} });

			std::string processJson = jsonBuffer.dump();
			
			continue;
		}
		BOOL bQuitIndicated = FALSE;

		jip.ProcessJsonInput(testJsonBuffer, outputQueue, incomingRuleQueue, bQuitIndicated);

		if (bQuitIndicated)
			ceaseRequested.store(true);
	}
}
void WriteOutput(AtomicBool & ceaseRequested, JsonQueue & outputQueue)
{
	while (false == ceaseRequested.load()) {
		json item;
		if (outputQueue.wait_dequeue_timed(item, chrono::milliseconds(1000))) {
			cout << item << endl;
		}
	}
}

void HashProcesses(
	AtomicBool &       ceaseRequested,
	JsonQueue &        outputQueue,
	WStringQueue &     requestQueue,
	ProcessHashQueue & resultQueue)
{
	wstring item;

	while (false == ceaseRequested.load()) {
		if (requestQueue.wait_dequeue_timed(item, chrono::milliseconds(1000))) {
			try {
				NTSTATUS status;

				std::wstring hashProduced;

				BOOL bHashCalcSuccessful = HashCalc(item, BCRYPT_SHA256_ALGORITHM, status, hashProduced);

				if (bHashCalcSuccessful) {
					resultQueue.enqueue({ item, hashProduced });
				}
				else
				{
					outputQueue.enqueue(json({ {"command", "produce hash"}, {"errors", status} }));
				}
			}
			catch (exception & ex) {
				outputQueue.enqueue(json({ {"command", "produce hash"}, {"exceptionj", ex.what()} }));
			}


			/*wstringstream hashStream;
			hashStream << uppercase << hex;
			for (const int & i : hashIntVector) { hashStream << setfill(L'0') << setw(2) << i; }
			wstring sha256 = hashStream.str();
			resultQueue.enqueue(ProcessHash({ item, sha256 })); */
			//fhc.CalcFileHash(item, resultQueue);
		}
	}
}




// read file
// DWORD      dwBytesRead            = 0;
// char       ReadBuffer[BUFFERSIZE] = {0};
// OVERLAPPED ol                     = {0};
// if (FALSE == ReadFileEx(hFile, ReadBuffer, BUFFERSIZE - 1, &ol, FileIOCompletionRoutine)) {
//     DisplayError(TEXT("ReadFile"));
//     printf("Terminal failure: Unable to read from file.\n GetLastError=%08x\n", GetLastError());
//     CloseHandle(hFile);
//     return;
// }
// SleepEx(5000, TRUE);
// dwBytesRead = g_BytesTransferred;
// // This is the section of code that assumes the file is ANSI text.
// // Modify this block for other data types if needed.
//
// if (dwBytesRead > 0 && dwBytesRead <= BUFFERSIZE - 1) {
//     ReadBuffer[dwBytesRead] = '\0'; // NULL character
//
//     _tprintf(TEXT("Data read from %s (%d bytes): \n"), argv[1], dwBytesRead);
//     printf("%s\n", ReadBuffer);
// } else if (dwBytesRead == 0) {
//     _tprintf(TEXT("No data read from file %s\n"), argv[1]);
// } else {
//     printf("\n ** Unexpected value for dwBytesRead ** \n");
// }

//hashEngine.Update(targetFile.GetFileDataPtr(), targetBytes);
//auto hashIntVector = hashEngine.Finish();

//wstringstream hashStream;
//hashStream << uppercase << hex;
//for (const int & i : hashIntVector) { hashStream << setfill(L'0') << setw(2) << i; }
//wstring sha256 = hashStream.str();
//resultQueue.enqueue(ProcessHash({item, sha256}));
//} catch (...) {
	// pass
//}
//}
//}
//}

vector<Process> GetProcesses(JsonQueue & outputQueue)
{
	vector<Process> result;

	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcess;

	auto enumProcessesResult = EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);
	if (0 == enumProcessesResult) {
		throw runtime_error("Error");//GetLastErrorMessage());
	}

	cProcess = cbNeeded / sizeof(DWORD);
	for (unsigned int i = 0; i < cProcess; i++) {
		auto processId = aProcesses[i];
		if (0 == processId) {
			continue;
		}

		DWORD  desiredAccess = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		BOOL   inheritHandle = FALSE;
		HANDLE processHandle = OpenProcess(desiredAccess, inheritHandle, processId);
		if (NULL == processHandle) {
			continue;
		}

		wstring processName;
		try {
			processName = GetModuleName(processHandle);
		}
		catch (exception & ex) {
			outputQueue.enqueue(json({ {"command", "get module name"}, {"errors", ex.what()} }));
			processName = L"<unknown>";
		}

		wstring processImageFullPath;

		auto processImageFileName = GetProcessImageFileNameW_(processHandle);
		if (L"" == processImageFileName) {
			processImageFullPath = L"<unknown>";
		}
		else {
			processImageFullPath = MapWin32FileName(processImageFileName);
		}

		result.push_back(Process({ ulong(processId), processName, processImageFullPath }));

		BOOL closeHandleResult = CloseHandle(processHandle);
		if (0 == closeHandleResult) {
			throw runtime_error("ERROR");//GetLastErrorMessage());
		}
	}

	return result;
}
