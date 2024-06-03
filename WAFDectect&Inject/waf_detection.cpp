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
		auto const host = url.substr(url.find("://") + 3);
		auto const port = "9973";
		auto const target = url.substr(url.find(host) + host.length());

		net::io_context ioContext;
		tcp::resolver resolver(ioContext);
		beast::tcp_stream stream(ioContext);

		auto const results = resolver.resolve(host, port);
		stream.connect(results);

		http::request<http::string_body> req{ http::verb::get, target, 11 };
		req.set(http::field::host, host);
		req.set(http::field::user_agent, "");

		http::write(stream, req);

		beast::flat_buffer buffer;
		http::response<http::string_body> res;

		http::read(stream, buffer, res);

		beast::error_code errorCode;
		stream.socket().shutdown(tcp::socket::shutdown_both, errorCode);

		if (errorCode && errorCode != beast::errc::not_connected)
			throw beast::system_error{ errorCode };

		return res.body(); // Right I need to think about this, it coudl be right, my thinking is to pull headers rn
	}
	catch (std::exception const& error) {
		std::cerr << "Error: " << error.what() << std::endl;
		return "Error in makeReqest";
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
	std::string response = makeRequest(url);

	for (const auto& signature : signatures){


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
		if (!signature.headers.empty() && std::regex_search(response, std::regex(signature.headers))) {
			return signature.name;
		}

}

	//Maybe some behavior analysis? I will come back to this
	std::string xssPayload = "%3Cscript%3Ealert('XSS')%3C/script%3E";
	std::string xssResponse = makeRequest(url + xssPayload);
	if (xssResponse.find(xssPayload) != std::string::npos) {
		return "No WAG detected (Payload reflected";
	}


	return "Unknown";
}

