#include "waf_detection.h"
#include <boost/beast/core.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <regex>

//some clean up on namespace callsigns
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;

std::string makeRequest(const std::string& url) {
	try {
			std::string fullUrl = url;
			if (fullUrl.substr(0, 7) != "http://" && fullUrl.substr(0, 8) != "https://") {
					fullUrl = "http://" + fullUrl;
			}
			auto const hostStart = fullUrl.find("://") + 3;
			auto const hostEnd = fullUrl.find('/', hostStart);
			auto const host = fullUrl.substr(hostStart, hostEnd - hostStart);
			auto const port = fullUrl.substr(0, 5) == "https" ? "443" : "80";
			auto const target = (hostEnd != std::string::npos) ? fullUrl.substr(hostEnd) : "/";

			net::io_context ioContext;
			tcp::resolver resolver(ioContext);
			beast::tcp_stream stream(ioContext);

			auto const results = resolver.resolve(host, port);
			if (results.empty()) {
				throw std::runtime_error("Failed to resolve the hostname");
			}
			stream.connect(results);

			http::request<http::string_body> req{ http::verb::get, target, 11 };
			req.set(http::field::host, host);
			req.set(http::field::user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36");

			http::write(stream, req);

			beast::flat_buffer buffer;
			http::response<http::string_body> res;

			http::read(stream, buffer, res);

			beast::error_code errorCode;
			stream.socket().shutdown(tcp::socket::shutdown_both, errorCode);

			if (errorCode && errorCode != beast::errc::not_connected)
				throw beast::system_error{ errorCode };

			return res.body(); // Right I need to think about this, it coudl be right, my thinking is to pull headers rn
	} catch (std::exception const& error) {
		std::cerr << "Error: " << error.what() << std::endl;
		return "Error in makeReqest" + std::string(error.what());
	}
}

std::vector<WafSignature> loadWafSignatures(const std::string& filename) {
	std::vector<WafSignature> signatures;
	std::ifstream file(filename);
	if (file.is_open()) {
		json data;
		file >> data;
		for (const auto& item : data.items()) {
			WafSignature signature;
			signature.name = item.key();
			signature.headers = item.value()["code"];
			signature.page = item.value()["page"];
			signature.headers = item.value()["headers"];
			signatures.push_back(signature);

		}
		file.close();
	}
	return signatures;
}

std::string detectWAF(const std::string& url, const std::vector<WafSignature>& signatures) {
	try {
		std::string response = makeRequest(url);

		for (const auto& signature : signatures) {


			//check if the response code matches the signature
			if (!signature.code.empty() && response.find("HTTP/1.1 " + signature.code) != std::string::npos)
			{
				return signature.name;
			}

			//check if the reponse page matches the signature
			if (!signature.page.empty() && std::regex_search(response, std::regex(signature.page))) {
				return signature.name;
			}

			//check if the response headers match the signature
			std::vector<std::string> headerNames;
			std::istringstream iss(signature.headers);
			std::string header;
			while (std::getline(iss, header, '|')) {
				headerNames.push_back(header);
			}

			for (const auto& headerName : headerNames) {
				if (response.find(headerName) != std::string::npos) {
					return signature.name;
				}
			}

		}

		//Maybe some behavior analysis? I will come back to this
		std::string xssPayload = "%3Cscript%3Ealert('XSS')%3C/script%3E";
		std::string xssResponse = makeRequest(url + xssPayload);
		if (xssResponse.find(xssPayload) != std::string::npos) {
			return "No WAG detected (Payload reflected";
		}
	}
	catch (const boost::system::system_error& e) {
		if (e.code() == boost::asio::error::host_not_found) {
			return "No WAF detected (hostname resolution failed)";
		}
		else {
			throw;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return "Error in WAF detection: " + std::string(e.what());
	}

	return "Unknown";
}

