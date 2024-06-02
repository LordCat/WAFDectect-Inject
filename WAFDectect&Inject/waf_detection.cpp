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
		for (const auto& item : data) {
			WafSignature signature;
			signature.name = item["name"];
			signature.headers = item["headers"].get<std::vector<std::string>>();
			signature.body = item["body"].get<std::vector<std::string>>();
			signatures.push_back(signature);
		}
		file.close();
	}
	return signatures;
}

std::string detectWAF(const std::string& url, const std::vector<WafSignature>& signatures) {
	std::string response = makeRequest(url);

	for (const auto& signature : signatures) {
		bool headerMatch = false;
		for (const auto& header : signature.headers) {
			if (response.find(header) != std::string::npos) {
				headerMatch = true;
				break;
			}
		}

		bool bodyMatch = false;
		for (const auto& pattern : signature.body) {
			if (response.find(pattern) != std::string::npos) {
				bodyMatch = true;
				break;
			}
		}

		if (headerMatch || bodyMatch) {
			return signature.name;
		}

	}

	//Maybe some behavior analysis? I will come back to this


	return "Unknown";
}

