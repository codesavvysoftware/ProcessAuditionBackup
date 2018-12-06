// clang-format off
#include "ProcessAuditingDefs.hpp"
#include "ThreadBase.hpp"
#include "HashCalc.hpp"
#include <sstream>      // std::istringstream
#include "string_stream_buffer.hpp"
#include "char_array_buffer.hpp" 


int main()
{
	// output original and patched document
	//std::cout << std::setw(4) << document << std::endl;	//TestEncrypting();
	//TestEncrypting();

    auto hashingEnabled = true;
    auto hashingWanted  = false;

    AtomicBool ceaseRequested(false);

	std::string rawData = R"({"command":"put rules","content":[{"identification":"0","specs":[{"filename":"powershell.exe"},{"filename":"reg.exe"},{"filename":"vssadmin.exe"},{"filename":"ntdsutil.exe"},{"filename":"regsvr32.exe"},{"filename":"mshta.exe"}]}]})";
	std::string quitCmd = R"({command":"quit"})";
	std::stringstream sRawForJSON(rawData);

	auto cin_buff = std::cin.rdbuf(sRawForJSON.rdbuf()); // substitute internal std::cout buffer with
	//rawData += "\n";
	//quitCmd += "\n";
	//ReusableClasses::string_stream_buffer customBuffer(rawData);

	//ReusableClasses::char_array_buffer charBuffer(rawData.c_str(), rawData.length());

	//std::stringstream sRawForJSON(rawData);

	//auto cin_buff = std::cin.rdbuf(sRawForJSON.rdbuf()); // substitute internal std::cout buffer with
    //	std::cin.rdbuf(cin_buff);
	//std::string rawDataX;

	//std::getline(cin, rawDataX);

	//sRawForJSON.str(quitCmd);


	//std::string rawDataY;
	//std::getline(cin, rawDataY);
	//sRawForJSON.str(rawData);


	//std::cin.rdbuf(cin_buff);
	//std::getline(cin, rawDataY);

	//iss rawData;	

	//std::cin.rdbuf(cin_buff);
	JsonQueue         outputQueue;
    RuleQueue         incomingRuleQueue;
    RuleVector        currentRules;
    ProcessHashQueue  hashingResults;
    WStringQueue      hashingRequests;
    ProcessHashVector currentHashes;

    thread outputThread(WriteOutput, ref(ceaseRequested), ref(outputQueue));
	thread_guard outputThreadGuard(outputThread);

    thread hashingThread(
        HashProcesses, ref(ceaseRequested), ref(outputQueue), ref(hashingRequests), ref(hashingResults));
	thread_guard hashingThreadGuard(hashingThread);

	thread processInputThread(ProcessInput, ref(ceaseRequested), ref(outputQueue), ref(incomingRuleQueue));
	thread_guard processInputThreadGuard(processInputThread);
	

    while (false == ceaseRequested.load()) {
        Rule incomingRule;
        if (incomingRuleQueue.wait_dequeue_timed(incomingRule, chrono::milliseconds(100))) {
			cout << endl;
			
			for (const Spec & s : incomingRule.specs)
			{
				cout << "Match Type: ";
				cout << s.matchType;
				cout << "        ";
				cout << "Match Value: ";
				cout << s.matchValu;
				cout << endl;
			}
            auto updated = false;
            for (size_t i = 0; i < currentRules.size(); i++) {
                if (currentRules[i].ident == incomingRule.ident) {
                    currentRules[i] = incomingRule;

                    updated = true;
                    break;
                }
            }
            if (false == updated) {
                for (const Spec & s : incomingRule.specs) {
                    if ("sha256" == s.matchType) {
                        hashingWanted = true;
                    }
                }
                currentRules.push_back(incomingRule);
            }
        }

        if (hashingEnabled && hashingWanted) {
            ProcessHash hashingResult;
            bool        hashingResultDequeued;
            do {
                hashingResultDequeued = hashingResults.try_dequeue(hashingResult);
                if (hashingResultDequeued) {
                    currentHashes.push_back(hashingResult);
                }
            } while (hashingResultDequeued);
        }

        try {
            auto currentProcesses = GetProcesses(outputQueue);
            for (const Process & p : currentProcesses) {
                // wcout << wstring(p) << endl;
                if (hashingWanted && hashingEnabled) {
                    hashingRequests.enqueue(p.fullpath);
                }
                for (const Rule & r : currentRules) {
                    for (const Spec & s : r.specs) {
						if ("sha256" == s.matchType) {
							for (ProcessHash hash : currentHashes) {
								std::string hashAsciiHexVal;

								ConvertWstrToAsciiHexStr(hash.sha256, hashAsciiHexVal);

								if (hashAsciiHexVal == s.matchValu) {
								//resultQueue
								// Check for Hash in
								// Check Spec for Match
								}
							}
						}
                    }
                }
            }

        } catch (exception & ex) {
            outputQueue.enqueue(json({{"command", "get processes"}, {"errors", ex.what()}}));
        }

        // Loop over Queue and Select an Exe to Hash (one that is not currently in )

        this_thread::sleep_for(30s);

		sRawForJSON.str(quitCmd);

    }

    ceaseRequested.store(true);

	std::cin.rdbuf(cin_buff);

	processInputThread.join();
    hashingThread.join();
    outputThread.join();

    return 0;
}
