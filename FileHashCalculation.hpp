#pragma once
#include "ProcessAuditingDefs.hpp"
class FileHashCalculation {
public:
	FileHashCalculation() {}
	~FileHashCalculation() {}
	void CalcFileHash(wstring item, ProcessHashQueue & resultQueue);
private:
	static const DWORD BFRSIZE = 1024;
};