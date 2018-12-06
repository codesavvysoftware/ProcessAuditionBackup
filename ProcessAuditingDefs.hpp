#pragma once
#include "Precompiled.hpp"
#include "Structures.hpp"


// clang-format on

using namespace std;
using namespace moodycamel;

using json = nlohmann::json;

using ulong = unsigned long;

using AtomicBool = atomic<bool>;

using JsonQueue = BlockingConcurrentQueue<json>;
using RuleQueue = BlockingConcurrentQueue<Rule>;
using WStringQueue = BlockingConcurrentQueue<wstring>;
using ProcessHashQueue = BlockingConcurrentQueue<ProcessHash>;

using RuleVector = vector<Rule>;
using ProcessHashVector = vector<ProcessHash>;

