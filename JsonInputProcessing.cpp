#include "JsonInputProcessing.hpp"

void JsonInputProcessing::ProcessJsonInput(json & jsonBuffer, JsonQueue & outputQueue, RuleQueue & incomingRuleQueue, BOOL & bQuitAppIndicated) {
	
	auto command = jsonBuffer.find("command");

	bQuitAppIndicated = FALSE;
	
	if (jsonBuffer.end() == command) {
		jsonBuffer.merge_patch(json({ {"errors", {"missing command"}} }));
	} else if ("quit" == *command) {		
		bQuitAppIndicated = TRUE;

		jsonBuffer.merge_patch(json({ {"response", "acknowledged"} }));
	} else if ("ping" == *command) {
		jsonBuffer.merge_patch(json({ {"response", "pong"} }));
	} else if ("put rules" == *command) {
		auto content = jsonBuffer.find("content");
		
		if (jsonBuffer.end() == content) {
			jsonBuffer.merge_patch(json({ {"errors", {"missing content"}} }));
		}
		else {
			RuleVector rules;
			try {
				rules = (*content).get<vector<Rule>>();
			}
			catch (exception & ex) {
				vector<string> errors = { "parsing content", ex.what() };
				jsonBuffer.merge_patch(json({ {"errors", errors} }));
				outputQueue.enqueue(jsonBuffer);
				return;
			}
			for (const Rule & r : rules) { incomingRuleQueue.enqueue(r); }
			jsonBuffer.merge_patch(json({ {"content", rules} }));
			auto outputStr = jsonBuffer.dump();
			cout << outputStr;

			int i = 0;
		}
	} else {
		jsonBuffer.merge_patch(json({ {"errors", {"unknown command"}} }));
	}
	
	outputQueue.enqueue(jsonBuffer);
}
