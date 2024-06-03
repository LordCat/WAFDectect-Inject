// WAFDectect&Inject.cpp : This file contains the 'main' function. Program execution begins and ends there.
// Welcometo WAF-DETECT&INJECT
// Idealy version one will take a root url "www.example.com/" and a CSV/JSON file inputs. 
// It will then probe for WAF, detect it, and then use a relavent payload list tailored for each WAF enouncter.
// It will return what is blocked, filthered and bypassed. Maybe even highlight results worth more attention 
// or manual testing. 


#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>

#include "waf_detection.h"

int main(int argc, char* argv[]){
    if (argc != 2) {
     std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
     return 1; //Invalid Usage 
    }

    std::string url = argv[1]; // Get the URL from the cli command.

    //Check if the arg is a URL. 
    if (url.substr(0, 4) != "www.") { 
        std::cerr << "Invalid URL, URL should start with www.";
        return 1; //Invalid usage
    }

    std::cout << "URL: " << url << std::endl;

    std::vector<WafSignature> signatures = loadWafSignatures("WAF_Signatures.json");
    std::string wafResult = detectWAF(url, signatures);

    std::cout << "WAF detection result: " << wafResult << std::endl;


    return 0; //Nominel Termination
}


