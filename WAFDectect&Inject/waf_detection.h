#pragma once

#ifndef WAF_DETECTION_H
#define WAF_DETECTION_H


#include <string>
#include <vector>
#include <nlohmann/json.hpp>

//Define the WAFSignature Datatype 
struct WafSignature {
	std::string name;
	std::vector<std::string> headers;
	std::vector<std::string> body;
};


std::string makeRequest(const std::string& url);
std::vector<WafSignature> loadWafSignatures(const std::string& filename);

std::string detectWAF(const std::string& url, const std::vector<WafSignature>& signatures);


#endif