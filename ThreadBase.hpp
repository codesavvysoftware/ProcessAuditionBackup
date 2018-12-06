#pragma once
#include <queue>
void ProcessInput(AtomicBool & ceaseRequested, JsonQueue & outputQueue, RuleQueue & incomingRuleQueue);
void WriteOutput(AtomicBool & ceaseRequested, JsonQueue & outputQueue);
void HashProcesses(
	AtomicBool &       ceaseRequested,
	JsonQueue &        outputQueue,
	WStringQueue &     requestQueue,
	ProcessHashQueue & resultQueue);
vector<Process> GetProcesses(JsonQueue & outputQueue);

class thread_guard {
	std::thread & t;
public:
	explicit thread_guard(std::thread & t_) : t(t_) {}
	~thread_guard() {
		if (t.joinable()) {
			t.join();
		}
	}
	thread_guard(thread_guard const &) = delete;
	thread_guard & operator = (thread_guard const &) = delete;
};
