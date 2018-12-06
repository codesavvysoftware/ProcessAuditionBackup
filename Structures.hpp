#pragma once
#ifndef STRUCTURES_HPP
#    define STRUCTURES_HPP
#    include "Precompiled.hpp"

struct Process {
    unsigned long id;
    std::wstring  filename;
    std::wstring  fullpath;

    operator std::wstring() const;
};

struct Spec {
    /*
        https://git.bds.local/vision/server/blob/844a9bb59b2851ab2216eb99494ca39ef972ceae/src/BDS.Vision.Collection/DTO.fs#L28
    */
    std::string matchType; /* filename, fullpath, pathglob, sha256 */
    std::string matchValu;
};
void to_json(nlohmann::json & j, const Spec & s);
void from_json(const nlohmann::json & j, Spec & s);

struct Rule {
    std::string       ident;
    std::vector<Spec> specs;
};
void to_json(nlohmann::json & j, const Rule & r);
void from_json(const nlohmann::json & j, Rule & r);

struct ProcessHash {
    std::wstring fullpath;
    std::wstring sha256;
};

#endif // STRUCTURES_HPP
