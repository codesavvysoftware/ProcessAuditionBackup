// clang-format off
#include "Precompiled.hpp"
#include "Structures.hpp"
// clang-format on

using namespace std;

using json = nlohmann::json;

Process::operator wstring() const
{
    wstringstream repr;
    // clang-format off
    repr << L"PID(" << id << L")"
         << L" ModuleBaseName(" << filename << L")"
         << L" ImageFileName(" << fullpath << ")"
    ;
    // clang-format on
    return repr.str();
}

/* ********************************** Spec ********************************** */

void to_json(json & j, const Spec & s)
{
    //
    j = json{{s.matchType, s.matchValu}};
}

void from_json(const json & j, Spec & s)
{
    s.matchValu = j.front().get<string>();

    vector<string> matchTypes = {"filename", "fullpath", "pathglob", "sha256"};
    for (const string & t : matchTypes) {
        auto match = j.find(t);
        if (j.end() != match) {
            s.matchType = t;
            break;
        }
    }
}

/* ********************************** Rule ********************************** */

void to_json(json & j, const Rule & r)
{
    //
    j = json{{"identification", r.ident}, {"specs", r.specs}};
}

void from_json(const json & j, Rule & r)
{
    r.ident = j.at("identification").get<string>();
    r.specs = j.at("specs").get<vector<Spec>>();
}
