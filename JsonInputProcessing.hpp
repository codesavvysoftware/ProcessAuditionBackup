#pragma once
#include "ProcessAuditingDefs.hpp"

class JsonInputProcessing {
public:
	JsonInputProcessing() {}
	~JsonInputProcessing() {}
	void ProcessJsonInput(json &, JsonQueue &, RuleQueue &, BOOL &);
};