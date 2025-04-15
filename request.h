//##############################
//版本：0.2
//作者：TimConner
//上传时间：2025/4/15 12：47
//##############################
#pragma once
#include <iostream>
#include <string>
#include <winsock2.h>
#include <list>
#include <ws2tcpip.h>
#include <sstream>
#include <regex>
#include <vector>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

//===============================================
//版本：0.2
//作者：TimConner
//===============================================


using namespace std;

class request {

	class PostRequest {
		// 请求的URL和端口
		string request_Url;
		int request_Port;

		// 定义解析后的URL结构体
		struct ParsedUrl {
			std::string protocol;  // 协议，例如 "http" 或 "https"
			std::string hostname;  // 主机名
			int port;              // 端口号
			std::string path;      // 路径部分
		};

		// 请求错误结构体，保存错误码和错误信息
		struct RequestErrorStruct {
			int errorId;
			string errorString;
			RequestErrorStruct() : errorId(0), errorString("") {}
		} requestError;

		// POST请求所需的各项头信息以及请求体
		struct PostRequestStruct {
			string contentType;      // 内容类型，例如 "application/json"
			int contentLength;       // 内容长度（字节数）
			string Authorization;    // 授权信息
			string userAgent;        // 客户端标识
			string accept;           // 接受的数据类型
			string acceptEncoding;   // 接受的编码格式
			string acceptLanguage;   // 接受的语言格式
			string referer;          // 来源页面
			string cookie;           // Cookie信息
			string connection;       // 连接方式，如 "close"
			string cacheControl;     // 缓存控制
			list<string> anotherHeader; // 其他自定义头

			string requestBody;      // 请求体
		};

		struct PostRequestBackStruct {
			int statusCode = 0;
			string contentType;
			int contentLength = 0;
			string Authorization;
			string userAgent;
			string accept;
			string acceptEncoding;
			string acceptLanguage;
			string referer;
			string cookie;
			string connection;
			string cacheControl;
			string host;
			string ifModifiedSince;
			list<pair<string, string>> anotherHeader;
			string requestBody;
		};

		// 正则表达式解析URL
		bool parseUrl(const std::string& url, ParsedUrl& parsed) {
			// 使用正则表达式匹配协议、主机名、端口和路径
			std::regex url_regex(
				R"(^(https?)://([^/:]+)(:(\d+))?(/(?:[^?#]*)?)?)"
			);
			std::smatch match;

			if (std::regex_search(url, match, url_regex)) {
				parsed.protocol = match[1].str();
				parsed.hostname = match[2].str();

				// 根据协议设置默认端口（https为443，http为80），同时处理显式指定的端口
				parsed.port = (parsed.protocol == "https") ? 443 : 80;
				if (match[4].matched) { // 存在显式的端口号
					parsed.port = std::stoi(match[4].str());
				}

				// 处理路径，若为空则设置为"/"
				parsed.path = match[5].str().empty() ? "/" : match[5].str();
				return true;
			}
			return false;
		}

		// 发送HTTP POST请求
		string sendHttpPostRequest(const std::string& requestBodySend) {
			// 初始化Winsock库
			WSADATA wsaData;
			if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
				std::ostringstream oss;
				oss << "WSAStartup failed. Error: " << WSAGetLastError();
				requestError.errorId = 1;
				requestError.errorString = oss.str();
				return "";
			}

			// 创建TCP套接字
			SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (sock == INVALID_SOCKET) {
				std::ostringstream oss;
				oss << "Socket creation failed. Error: " << WSAGetLastError();
				requestError.errorId = 2;
				requestError.errorString = oss.str();
				WSACleanup();
				return "";
			}

			// 解析域名，获取目标服务器地址信息
			struct addrinfo hints = {};
			struct addrinfo* result = nullptr;
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			if (getaddrinfo(parsedUrl.hostname.c_str(), std::to_string(parsedUrl.port).c_str(), &hints, &result) != 0) {
				requestError.errorId = 3;
				requestError.errorString = "Domain resolution failed";
				closesocket(sock);
				WSACleanup();
				return "";
			}

			// 连接到服务器
			if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
				requestError.errorId = 4;
				requestError.errorString = "Connection failed. Error: " + to_string(WSAGetLastError());
				freeaddrinfo(result);
				closesocket(sock);
				WSACleanup();
				return "";
			}
			freeaddrinfo(result);

			// 发送HTTP请求数据
			//cout << "send:" << endl << requestBodySend << endl;
			if (send(sock, requestBodySend.c_str(), requestBodySend.size(), 0) == SOCKET_ERROR) {
				std::ostringstream oss;
				oss << "Send failed. Error: " << WSAGetLastError();
				requestError.errorId = 5;
				requestError.errorString = oss.str();
				closesocket(sock);
				WSACleanup();
				return "";
			}

			// 接收服务器响应数据
			std::string response;
			char buffer[4096];
			int bytesReceived;
			while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
				response.append(buffer, bytesReceived);
			}

			// 错误处理
			if (bytesReceived < 0) {
				std::ostringstream oss;
				oss << "Receive failed. Error: " << WSAGetLastError();
				requestError.errorId = 6;
				requestError.errorString = oss.str();
			}

			// 关闭套接字并清理Winsock资源
			closesocket(sock);
			WSACleanup();

			return response;
		}

		// 构造HTTP POST请求头部
		string makePostHeader() {
			ostringstream requestStream;
			// 请求行：方法和请求路径
			requestStream << "POST " << parsedUrl.path << " HTTP/1.1\r\n";

			// Host头：包括主机名和必要时端口号
			if (!parsedUrl.hostname.empty()) {
				requestStream << "Host: " << parsedUrl.hostname;
				if (parsedUrl.port != 80 && parsedUrl.port != 443) { // 非默认端口需显示指定
					requestStream << ":" << parsedUrl.port;
				}
				requestStream << "\r\n";
			}

			// Content-Type头
			if (!postRequestHeader.contentType.empty()) {
				requestStream << "Content-Type: " << postRequestHeader.contentType << "\r\n";
			}

			// Content-Length头
			if (postRequestHeader.contentLength >= 0) {
				requestStream << "Content-Length: " << postRequestHeader.contentLength << "\r\n";
			}

			// Authorization头
			if (!postRequestHeader.Authorization.empty()) {
				requestStream << "Authorization: " << postRequestHeader.Authorization << "\r\n";
			}

			// User-Agent头
			if (!postRequestHeader.userAgent.empty()) {
				requestStream << "User-Agent: " << postRequestHeader.userAgent << "\r\n";
			}

			// Accept头
			if (!postRequestHeader.accept.empty()) {
				requestStream << "Accept: " << postRequestHeader.accept << "\r\n";
			}

			// Accept-Encoding头
			if (!postRequestHeader.acceptEncoding.empty()) {
				requestStream << "Accept-Encoding: " << postRequestHeader.acceptEncoding << "\r\n";
			}

			// Accept-Language头
			if (!postRequestHeader.acceptLanguage.empty()) {
				requestStream << "Accept-Language: " << postRequestHeader.acceptLanguage << "\r\n";
			}

			// Referer头
			if (!postRequestHeader.referer.empty()) {
				requestStream << "Referer: " << postRequestHeader.referer << "\r\n";
			}

			// Cookie头
			if (!postRequestHeader.cookie.empty()) {
				requestStream << "Cookie: " << postRequestHeader.cookie << "\r\n";
			}

			// Connection头
			if (!postRequestHeader.connection.empty()) {
				requestStream << "Connection: " << postRequestHeader.connection << "\r\n";
			}

			// Cache-Control头
			if (!postRequestHeader.cacheControl.empty()) {
				requestStream << "Cache-Control: " << postRequestHeader.cacheControl << "\r\n";
			}

			// 添加其他自定义头信息
			for (const auto& header : postRequestHeader.anotherHeader) {
				requestStream << header << "\r\n";
			}

			// 空行分隔头和体
			requestStream << "\r\n";
			return requestStream.str();
		}

		// 清除错误状态
		void cleanError() {
			requestError.errorId = 0;
			requestError.errorString = "";
		}
		string trim(const string& s) {
			size_t start = s.find_first_not_of(" \t");
			if (start == string::npos) return "";
			size_t end = s.find_last_not_of(" \t");
			return s.substr(start, end - start + 1);
		}

		// 辅助函数：将字符串转换为小写
		string toLower(const string& s) {
			string result = s;
			transform(result.begin(), result.end(), result.begin(),
				[](unsigned char c) { return tolower(c); });
			return result;
		}

		// 辅助函数：分割头部为行
		void splitHeaders(const string& headers, vector<string>& lines) {
			stringstream ss(headers);
			string line;
			while (getline(ss, line, '\n')) {
				// 去除每行末尾的\r
				if (!line.empty() && line.back() == '\r') {
					line.pop_back();
				}
				if (!line.empty()) {
					lines.push_back(line);
				}
			}
		}
		void parsePostRequest(const string& request, PostRequestBackStruct& result) {
			// 清空先前可能存在的数据
			result.anotherHeader.clear();

			// 分割请求头和请求体
			size_t headerEnd = request.find("\r\n\r\n");
			string headersPart, bodyPart;

			if (headerEnd != string::npos) {
				headersPart = request.substr(0, headerEnd);
				bodyPart = request.substr(headerEnd + 4); // 跳过\r\n\r\n
			}
			else {
				headerEnd = request.find("\n\n");
				if (headerEnd != string::npos) {
					headersPart = request.substr(0, headerEnd);
					bodyPart = request.substr(headerEnd + 2); // 跳过\n\n
				}
				else {
					headersPart = request;
					bodyPart = "";
				}
			}

			vector<string> headerLines;
			splitHeaders(headersPart, headerLines);

			// 处理HTTP响应起始行（如果存在）
			if (!headerLines.empty()) {
				string firstLine = headerLines[0];
				if (firstLine.compare(0, 5, "HTTP/") == 0) {
					// 提取状态码
					size_t firstSpace = firstLine.find(' ');
					if (firstSpace != string::npos) {
						size_t secondSpace = firstLine.find(' ', firstSpace + 1);
						if (secondSpace != string::npos) {
							string codeStr = firstLine.substr(
								firstSpace + 1,
								secondSpace - firstSpace - 1
							);
							try {
								result.statusCode = stoi(codeStr);
							}
							catch (...) {
								result.statusCode = 0;
							}
						}
					}
					headerLines.erase(headerLines.begin());
				}
			}

			// 处理每个请求头
			for (const string& line : headerLines) {
				size_t colonPos = line.find(':');
				if (colonPos == string::npos) {
					// 无效格式：存储整行作为key，value为空
					result.anotherHeader.emplace_back(line, "");
					continue;
				}

				// 分割键值对
				string key = trim(line.substr(0, colonPos));
				string value = trim(line.substr(colonPos + 1));
				string keyLower = toLower(key);

				// 处理已知Header类型
				if (keyLower == "content-type") {
					result.contentType = value;
				}
				else if (keyLower == "content-length") {
					try {
						result.contentLength = stoi(value);
					}
					catch (...) {
						result.contentLength = 0;
					}
				}
				else if (keyLower == "authorization") {
					result.Authorization = value;
				}
				else if (keyLower == "user-agent") {
					result.userAgent = value;
				}
				else if (keyLower == "accept") {
					result.accept = value;
				}
				else if (keyLower == "accept-encoding") {
					result.acceptEncoding = value;
				}
				else if (keyLower == "accept-language") {
					result.acceptLanguage = value;
				}
				else if (keyLower == "referer") {
					result.referer = value;
				}
				else if (keyLower == "cookie") {
					result.cookie = value;
				}
				else if (keyLower == "connection") {
					result.connection = value;
				}
				else if (keyLower == "cache-control") {
					result.cacheControl = value;
				}
				else if (keyLower == "host") {
					result.host = value;
				}
				else if (keyLower == "if-modified-since") {
					result.ifModifiedSince = value;
				}
				else {
					// 存储未知Header为键值对
					result.anotherHeader.emplace_back(key, value);
				}
			}

			result.requestBody = bodyPart;
		}

		void debug_mode() {
			ostringstream debug;
			debug << "------------------------------------Post debug start----------------------------------------" << endl;
			debug << "path:" << parsedUrl.path << endl;
			debug << "hostname:" << parsedUrl.hostname << endl;
			debug << "port:" << parsedUrl.port << endl;
			debug << "protocol:" << parsedUrl.protocol << endl;
			debug << endl << endl << endl;
			// 输出结构体的每个字段
			debug << "Content-Type: " << postRequestHeader.contentType << endl;
			debug << "Content-Length: " << (postRequestHeader.contentLength < 0 ? "NULL" : to_string(postRequestHeader.contentLength)) << endl;
			debug << "Authorization: " << (postRequestHeader.Authorization.empty() ? "NULL" : postRequestHeader.Authorization) << endl;
			debug << "User-Agent: " << (postRequestHeader.userAgent.empty() ? "NULL" : postRequestHeader.userAgent) << endl;
			debug << "Accept: " << (postRequestHeader.accept.empty() ? "NULL" : postRequestHeader.accept) << endl;
			debug << "Accept-Encoding: " << (postRequestHeader.acceptEncoding.empty() ? "NULL" : postRequestHeader.acceptEncoding) << endl;
			debug << "Accept-Language: " << (postRequestHeader.acceptLanguage.empty() ? "NULL" : postRequestHeader.acceptLanguage) << endl;
			debug << "Referer: " << (postRequestHeader.referer.empty() ? "NULL" : postRequestHeader.referer) << endl;
			debug << "Cookie: " << (postRequestHeader.cookie.empty() ? "NULL" : postRequestHeader.cookie) << endl;
			debug << "Connection: " << postRequestHeader.connection << endl;
			debug << "Cache-Control: " << (postRequestHeader.cacheControl.empty() ? "NULL" : postRequestHeader.cacheControl) << endl;

			// 输出其他自定义头
			if (postRequestHeader.anotherHeader.empty()) {
				debug << "AnotherHeader: NULL" << endl;
			}
			else {
				debug << "AnotherHeader:" << endl;
				for (const auto& item : postRequestHeader.anotherHeader) {
					debug << "  - " << item << endl;
				}
			}

			// 输出请求体
			debug << "Request Body: " << (postRequestHeader.requestBody.empty() ? "NULL" : postRequestHeader.requestBody) << endl;

			debug << endl << "##################Return the request##################" << endl << endl;

			debug << "Status Code: " << postRequestBackHeader.statusCode << endl;
			debug << "Content-Type: " << (postRequestBackHeader.contentType.empty() ? "NULL" : postRequestBackHeader.contentType) << endl;
			debug << "Content-Length: " << (postRequestBackHeader.contentLength < 0 ? "NULL" : to_string(postRequestBackHeader.contentLength)) << endl;
			debug << "Authorization: " << (postRequestBackHeader.Authorization.empty() ? "NULL" : postRequestBackHeader.Authorization) << endl;
			debug << "User-Agent: " << (postRequestBackHeader.userAgent.empty() ? "NULL" : postRequestBackHeader.userAgent) << endl;
			debug << "Accept: " << (postRequestBackHeader.accept.empty() ? "NULL" : postRequestBackHeader.accept) << endl;
			debug << "Accept-Encoding: " << (postRequestBackHeader.acceptEncoding.empty() ? "NULL" : postRequestBackHeader.acceptEncoding) << endl;
			debug << "Accept-Language: " << (postRequestBackHeader.acceptLanguage.empty() ? "NULL" : postRequestBackHeader.acceptLanguage) << endl;
			debug << "Referer: " << (postRequestBackHeader.referer.empty() ? "NULL" : postRequestBackHeader.referer) << endl;
			debug << "Cookie: " << (postRequestBackHeader.cookie.empty() ? "NULL" : postRequestBackHeader.cookie) << endl;
			debug << "Connection: " << (postRequestBackHeader.connection.empty() ? "NULL" : postRequestBackHeader.connection) << endl;
			debug << "Cache-Control: " << (postRequestBackHeader.cacheControl.empty() ? "NULL" : postRequestBackHeader.cacheControl) << endl;
			debug << "ifModifiedSince: " << (postRequestBackHeader.ifModifiedSince.empty() ? "NULL" : postRequestBackHeader.ifModifiedSince) << endl;
			debug << "host: " << (postRequestBackHeader.host.empty() ? "NULL" : postRequestBackHeader.host) << endl;
			// 输出其他自定义头
			if (postRequestBackHeader.anotherHeader.empty()) {
				debug << "AnotherHeader: NULL" << endl;
			}
			else {
				debug << "AnotherHeader:" << endl;
				for (const auto& item : postRequestBackHeader.anotherHeader) {
					debug << item.first << ":" << item.second << endl;
				}
			}

			// 输出请求体
			debug << "Request Back Body: " << (postRequestBackHeader.requestBody.empty() ? "NULL" : postRequestBackHeader.requestBody) << endl;

			debug << endl << endl << endl;
			auto tmp = getError();
			debug << "id:" << tmp.first << endl << "Error:" << tmp.second << endl;
			debug << "--------------------------------Post debug end----------------------------------------" << endl;

			cout << debug.str();

		}

	public:

		bool debugMode = false;
		ParsedUrl parsedUrl;                // 解析后的URL数据
		PostRequestStruct postRequestHeader; // POST请求使用的头信息和请求体
		PostRequestBackStruct postRequestBackHeader; //Post请求返回的请求头
		// 构造函数，设置默认的请求头参数
		PostRequest() {
			postRequestHeader.contentType = "application/json";
			postRequestHeader.contentLength = 0; // 默认内容长度为0
			postRequestHeader.Authorization = "";
			postRequestHeader.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
			postRequestHeader.accept = "";
			postRequestHeader.acceptEncoding = "";
			postRequestHeader.acceptLanguage = "";
			postRequestHeader.referer = "";
			postRequestHeader.cookie = "";
			postRequestHeader.connection = "close";
			postRequestHeader.cacheControl = "";
			postRequestHeader.requestBody = "";
		}

		// 获取错误码（获取后清除错误状态）
		pair<int, string> getError() {

			pair<int, string> tmp;
			tmp.first = requestError.errorId;
			tmp.second = requestError.errorString;


			cleanError();
			return tmp;
		}

		// 设置请求的URL
		void setUrl(string url) {
			request_Url = url;
		}

		// 设置请求端口
		void setPort(int port) {
			request_Port = port;
		}


		// 发送POST请求：构造完整请求并调用发送函数
		string SendPost(string sendRequest = "") {
			// 判断URL和端口是否合法
			if (request_Url == "" && (request_Port < 0 && request_Port > 65535)) {
				requestError.errorId = 10;
				requestError.errorString = "No valid URL or port specified.";
				return "";
			}

			// 设置请求体，并更新Content-Length
			postRequestHeader.requestBody = sendRequest;
			postRequestHeader.contentLength = sendRequest.length();

			// 解析URL，若解析失败则返回错误
			if (!parseUrl(request_Url, parsedUrl)) {
				requestError.errorId = 100;
				requestError.errorString = "Invalid URL format";
				return "";
			}

			// 构造完整的HTTP请求字符串（请求头 + 请求体）
			string mainRequest = makePostHeader() + postRequestHeader.requestBody;

			string recvMessage = sendHttpPostRequest(mainRequest);

			parsePostRequest(recvMessage, postRequestBackHeader);

			if (debugMode == true)
				debug_mode();

			return postRequestBackHeader.requestBody;

		}
		//外部暴露接口
		void manualGetBackHeader(string recvMessage) {
			parsePostRequest(recvMessage, postRequestBackHeader);
			//return p;
		}


		//提取返回的头
	};


	class GetRequest {
		//网页分解url
		struct ParsedUrl {
			string protocol;
			string hostname;
			int port;
			string path;
			string query;
			string fragment;
		} parsedUrl;
		//错误结构体
		struct GetRequestErrorStruct {
			int errorId = 0;
			string errorString;

			enum ErrorCode {
				REQUEST_NO_ERROR = 0,
				WINSOCK_INIT_FAILED = 1,
				SOCKET_CREATION_FAILED = 2,
				DNS_RESOLUTION_FAILED = 3,
				CONNECTION_FAILED = 4,
				SEND_FAILED = 5,
				RECEIVE_FAILED = 6,
				INVALID_URL = 100,
				EMPTY_URL = 101
			};
		} requestGetError;
		//get请求发送信息结构体
		struct GetRequestHeaderStruct {
			string contentType="application/json";      // 内容类型，例如 "application/json"
			int contentLength;       // 内容长度（字节数）
			string Authorization;    // 授权信息
			string userAgent;        // 客户端标识
			string accept;           // 接受的数据类型
			string acceptEncoding;   // 接受的编码格式
			string acceptLanguage;   // 接受的语言格式
			string referer;          // 来源页面
			string cookie;           // Cookie信息
			string connection="close";       // 连接方式，如 "close"
			string cacheControl;     // 缓存控制

			list<string> anotherHeader; // 其他自定义头

			string requestBody;      // 请求体
		};
		//get请求返回参数结构体
		struct GetRequestBackStruct {
			int statusCode = 0;
			string contentType;
			int contentLength = 0;
			string Authorization;
			string userAgent;
			string accept;
			string acceptEncoding;
			string acceptLanguage;
			string referer;
			string cookie;
			string connection;
			string cacheControl;
			string host;
			string ifModifiedSince;
			list<pair<string, string>> anotherHeader;
			string requestBody;
		};
		// 辅助函数
		string trim(const string& s) {
			auto start = s.find_first_not_of(" \t");
			auto end = s.find_last_not_of(" \t");
			return (start != string::npos) ? s.substr(start, end - start + 1) : "";
		}
		string toLower(const string& s) {
			string result = s;
			transform(result.begin(), result.end(), result.begin(), ::tolower);
			return result;
		}
		// URL编码函数
		string urlEncode(const string& value) {
			ostringstream escaped;
			escaped.fill('0');
			escaped << hex;

			for (unsigned char c : value) {
				// 保留路径中的合法字符
				if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' ||
					c == '/' || c == ':' || c == '@') {
					escaped << c;
				}
				// 查询参数中的特殊字符保留
				else if (c == '?' || c == '=' || c == '&' || c == ',') {
					escaped << c;
				}
				else {
					escaped << '%' << setw(2) << int(c);
				}
			}
			return escaped.str();
		}
		// 正则表达式解析URL
		bool GetParseUrl(const string& url, ParsedUrl &parseddecompositionUrlParsed) {
			try {
				// 构造正则表达式
				std::regex url_regex(
					R"(^(https?)://)"          // 协议 (group1)
					R"(([^/?#:]+))"            // 主机名 (group2)
					R"((?::(\d+))?)"           // 端口号 (group3，可选)
					R"((/?[^?#]*)?)"           // 路径 (group4，可选)
					R"((?:\?([^#]*))?)"        // 查询参数 (group5，可选)
					R"((?:#(.*))?)",           // 片段 (group6，可选)
					std::regex::icase);

				//std::cout << u8"正则表达式构造成功！" << std::endl;

				smatch match;
				if (!regex_match(url, match, url_regex)) {
					requestGetError.errorId = GetRequestErrorStruct::INVALID_URL;
					requestGetError.errorString = "Malformed URL";
					return false;
				}

				parseddecompositionUrlParsed.protocol = toLower(match[1].str());
				parseddecompositionUrlParsed.hostname = match[2].str();

				// 端口处理
				if (match[3].matched && !match[3].str().empty()) {
					try {
						parseddecompositionUrlParsed.port = stoi(match[3].str()); // 直接获取端口号，无需substr
					}
					catch (...) {
						requestGetError.errorId = GetRequestErrorStruct::INVALID_URL;
						requestGetError.errorString = "Invalid port number";
						return false;
					}
				}
				else {
					parseddecompositionUrlParsed.port = (parseddecompositionUrlParsed.protocol == "https") ? 443 : 80;
				}

				// 路径处理
				parseddecompositionUrlParsed.path = match[4].matched ? urlEncode(match[4].str()) : "/";

				// 处理查询参数和片段
				parseddecompositionUrlParsed.query = match[5].matched ? urlEncode(match[5].str()) : "";
				parseddecompositionUrlParsed.fragment = match[6].matched ? urlEncode(match[6].str()) : "";

				// 合并路径和查询参数
				if (!parseddecompositionUrlParsed.query.empty()) {
					parseddecompositionUrlParsed.path += "?" + parseddecompositionUrlParsed.query;
				}

				return true;
			}
			catch (const std::regex_error& e) {
				requestGetError.errorId = e.code();
				requestGetError.errorString = e.what();
				//std::cerr << u8"正则表达式构造失败，错误信息：" << e.what() << std::endl;
				//std::cerr << u8"错误代码：" << e.code() << std::endl;
			}
			catch (...) {
				requestGetError.errorId = 404;
				requestGetError.errorString = "An unpredictable error occurred in the ParseUrl function";
				//std::cerr << u8"发生未知异常！" << std::endl;
			}
			return false;
		}
		// 清除错误状态
		void cleanError() {
			requestGetError.errorId = 0;
			requestGetError.errorString = "";
		}
		//get请求构建
		string GetRequestHeaderMake() {
			ostringstream requestMake;
			requestMake << "GET " << parsedUrl.path << " HTTP/1.1\r\n";

			// Host头：包括主机名和必要时端口号
			if (!parsedUrl.hostname.empty()) {
				requestMake << "Host: " << parsedUrl.hostname;
				if (parsedUrl.port != 80 && parsedUrl.port != 443) { // 非默认端口需显示指定
					requestMake << ":" << parsedUrl.port;
				}
				requestMake << "\r\n";
			}

			// Content-Type头
			if (!getRequestHeader.contentType.empty()) {
				requestMake << "Content-Type: " << getRequestHeader.contentType << "\r\n";
			}


			// Authorization头
			if (!getRequestHeader.Authorization.empty()) {
				requestMake << "Authorization: " << getRequestHeader.Authorization << "\r\n";
			}

			// User-Agent头
			if (!getRequestHeader.userAgent.empty()) {
				requestMake << "User-Agent: " << getRequestHeader.userAgent << "\r\n";
			}

			// Accept头
			if (!getRequestHeader.accept.empty()) {
				requestMake << "Accept: " << getRequestHeader.accept << "\r\n";
			}

			// Accept-Encoding头
			if (!getRequestHeader.acceptEncoding.empty()) {
				requestMake << "Accept-Encoding: " << getRequestHeader.acceptEncoding << "\r\n";
			}

			// Accept-Language头
			if (!getRequestHeader.acceptLanguage.empty()) {
				requestMake << "Accept-Language: " << getRequestHeader.acceptLanguage << "\r\n";
			}

			// Referer头
			if (!getRequestHeader.referer.empty()) {
				requestMake << "Referer: " << getRequestHeader.referer << "\r\n";
			}

			// Cookie头
			if (!getRequestHeader.cookie.empty()) {
				requestMake << "Cookie: " << getRequestHeader.cookie << "\r\n";
			}

			// Connection头
			if (!getRequestHeader.connection.empty()) {
				requestMake << "Connection: " << getRequestHeader.connection << "\r\n";
			}

			// Cache-Control头
			if (!getRequestHeader.cacheControl.empty()) {
				requestMake << "Cache-Control: " << getRequestHeader.cacheControl << "\r\n";
			}

			// 添加其他自定义头信息
			for (const auto& header : getRequestHeader.anotherHeader) {
				requestMake << header << "\r\n";
			}

			// 空行分隔头和体
			requestMake << "\r\n";
			return requestMake.str();
			/*
			string requestGet = "GET " + parsedUrl.path + " HTTP/1.1\r\n"
				+ "Host: " + parsedUrl.hostname
				+ (parsedUrl.port != 80 && parsedUrl.port != 443 ?
					":" + to_string(parsedUrl.port) : "")
				+ "\r\n"
				+ "User-Agent: C++HTTPClient/1.0\r\n"
				+ "Connection: close\r\n\r\n";
	*/

		}
		//发送请求主函数
		string sendHttpGetRequest() {
			WSADATA wsaData;
			if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
				requestGetError.errorId = GetRequestErrorStruct::WINSOCK_INIT_FAILED;
				requestGetError.errorString = "WSAStartup failed";
				return "";
			}

			SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sock == INVALID_SOCKET) {
				requestGetError.errorId = GetRequestErrorStruct::SOCKET_CREATION_FAILED;
				requestGetError.errorString = "Socket creation failed";
				WSACleanup();
				return "";
			}

			addrinfo hints = {}, * result;
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;

			if (getaddrinfo(parsedUrl.hostname.c_str(),
				to_string(parsedUrl.port).c_str(),
				&hints, &result) != 0) {
				requestGetError.errorId = GetRequestErrorStruct::DNS_RESOLUTION_FAILED;
				requestGetError.errorString = "DNS resolution failed";
				closesocket(sock);
				WSACleanup();
				return "";
			}

			if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
				requestGetError.errorId = GetRequestErrorStruct::CONNECTION_FAILED;
				requestGetError.errorString = "Connection failed";
				freeaddrinfo(result);
				closesocket(sock);
				WSACleanup();
				return "";
			}
			freeaddrinfo(result);
			/*
					string requestGet = "GET " + parsedUrl.path + " HTTP/1.1\r\n"
						+ "Host: " + parsedUrl.hostname
						+ (parsedUrl.port != 80 && parsedUrl.port != 443 ?
							":" + to_string(parsedUrl.port) : "")
						+ "\r\n"
						+ "User-Agent: C++HTTPClient/1.0\r\n"
						+ "Connection: close\r\n\r\n";
			*/
			string requestGet = GetRequestHeaderMake();

			if (send(sock, requestGet.c_str(), requestGet.size(), 0) == SOCKET_ERROR) {
				requestGetError.errorId = GetRequestErrorStruct::SEND_FAILED;
				requestGetError.errorString = "Send failed";
				closesocket(sock);
				WSACleanup();
				return "";
			}

			string response;
			char buffer[4096];
			int bytesReceived;
			while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0))) {
				if (bytesReceived < 0) break;
				response.append(buffer, bytesReceived);
			}

			closesocket(sock);
			WSACleanup();

			if (bytesReceived < 0) {
				requestGetError.errorId = GetRequestErrorStruct::RECEIVE_FAILED;
				requestGetError.errorString = "Receive error";
			}

			return response;
		}
		// 辅助函数：分割头部为行
		void splitHeaders(const string& headers, vector<string>& lines) {
			stringstream ss(headers);
			string line;
			while (getline(ss, line, '\n')) {
				// 去除每行末尾的\r
				if (!line.empty() && line.back() == '\r') {
					line.pop_back();
				}
				if (!line.empty()) {
					lines.push_back(line);
				}
			}
		}
		void parsePostRequest(const string& request, GetRequestBackStruct& result) {
			// 清空先前可能存在的数据
			result.anotherHeader.clear();

			// 分割请求头和请求体
			size_t headerEnd = request.find("\r\n\r\n");
			string headersPart, bodyPart;

			if (headerEnd != string::npos) {
				headersPart = request.substr(0, headerEnd);
				bodyPart = request.substr(headerEnd + 4); // 跳过\r\n\r\n
			}
			else {
				headerEnd = request.find("\n\n");
				if (headerEnd != string::npos) {
					headersPart = request.substr(0, headerEnd);
					bodyPart = request.substr(headerEnd + 2); // 跳过\n\n
				}
				else {
					headersPart = request;
					bodyPart = "";
				}
			}

			vector<string> headerLines;
			splitHeaders(headersPart, headerLines);

			// 处理HTTP响应起始行（如果存在）
			if (!headerLines.empty()) {
				string firstLine = headerLines[0];
				if (firstLine.compare(0, 5, "HTTP/") == 0) {
					// 提取状态码
					size_t firstSpace = firstLine.find(' ');
					if (firstSpace != string::npos) {
						size_t secondSpace = firstLine.find(' ', firstSpace + 1);
						if (secondSpace != string::npos) {
							string codeStr = firstLine.substr(
								firstSpace + 1,
								secondSpace - firstSpace - 1
							);
							try {
								result.statusCode = stoi(codeStr);
							}
							catch (...) {
								result.statusCode = 0;
							}
						}
					}
					headerLines.erase(headerLines.begin());
				}
			}

			// 处理每个请求头
			for (const string& line : headerLines) {
				size_t colonPos = line.find(':');
				if (colonPos == string::npos) {
					// 无效格式：存储整行作为key，value为空
					result.anotherHeader.emplace_back(line, "");
					continue;
				}

				// 分割键值对
				string key = trim(line.substr(0, colonPos));
				string value = trim(line.substr(colonPos + 1));
				string keyLower = toLower(key);

				// 处理已知Header类型
				if (keyLower == "content-type") {
					result.contentType = value;
				}
				else if (keyLower == "content-length") {
					try {
						result.contentLength = stoi(value);
					}
					catch (...) {
						result.contentLength = 0;
					}
				}
				else if (keyLower == "authorization") {
					result.Authorization = value;
				}
				else if (keyLower == "user-agent") {
					result.userAgent = value;
				}
				else if (keyLower == "accept") {
					result.accept = value;
				}
				else if (keyLower == "accept-encoding") {
					result.acceptEncoding = value;
				}
				else if (keyLower == "accept-language") {
					result.acceptLanguage = value;
				}
				else if (keyLower == "referer") {
					result.referer = value;
				}
				else if (keyLower == "cookie") {
					result.cookie = value;
				}
				else if (keyLower == "connection") {
					result.connection = value;
				}
				else if (keyLower == "cache-control") {
					result.cacheControl = value;
				}
				else if (keyLower == "host") {
					result.host = value;
				}
				else if (keyLower == "if-modified-since") {
					result.ifModifiedSince = value;
				}
				else {
					// 存储未知Header为键值对
					result.anotherHeader.emplace_back(key, value);
				}
			}

			result.requestBody = bodyPart;
		}

		void debug_mode() {
			ostringstream debug;
			debug << "------------------------------------Get debug start----------------------------------------" << endl;
			debug << "path:" << parsedUrl.path << endl;
			debug << "hostname:" << parsedUrl.hostname << endl;
			debug << "port:" << parsedUrl.port << endl;
			debug << "fragment:" << parsedUrl.fragment << endl;
			debug << "protocol:" << parsedUrl.protocol << endl;
			debug << "query:" << parsedUrl.query << endl;
			debug << endl << endl << endl;
			// 输出结构体的每个字段
			debug << "Content-Type: " << getRequestHeader.contentType << endl;
			debug << "Content-Length: " << (getRequestHeader.contentLength < 0 ? "NULL" : to_string(getRequestHeader.contentLength)) << endl;
			debug << "Authorization: " << (getRequestHeader.Authorization.empty() ? "NULL" : getRequestHeader.Authorization) << endl;
			debug << "User-Agent: " << (getRequestHeader.userAgent.empty() ? "NULL" : getRequestHeader.userAgent) << endl;
			debug << "Accept: " << (getRequestHeader.accept.empty() ? "NULL" : getRequestHeader.accept) << endl;
			debug << "Accept-Encoding: " << (getRequestHeader.acceptEncoding.empty() ? "NULL" : getRequestHeader.acceptEncoding) << endl;
			debug << "Accept-Language: " << (getRequestHeader.acceptLanguage.empty() ? "NULL" : getRequestHeader.acceptLanguage) << endl;
			debug << "Referer: " << (getRequestHeader.referer.empty() ? "NULL" : getRequestHeader.referer) << endl;
			debug << "Cookie: " << (getRequestHeader.cookie.empty() ? "NULL" : getRequestHeader.cookie) << endl;
			debug << "Connection: " << getRequestHeader.connection << endl;
			debug << "Cache-Control: " << (getRequestHeader.cacheControl.empty() ? "NULL" : getRequestHeader.cacheControl) << endl;

			// 输出其他自定义头
			if (getRequestHeader.anotherHeader.empty()) {
				debug << "AnotherHeader: NULL" << endl;
			}
			else {
				debug << "AnotherHeader:" << endl;
				for (const auto& item : getRequestHeader.anotherHeader) {
					debug << "  - " << item << endl;
				}
			}

			// 输出请求体
			debug << "Request Body: " << (getRequestHeader.requestBody.empty() ? "NULL" : getRequestHeader.requestBody) << endl;

			debug <<endl<< "##################Return the request##################" << endl<<endl;

			debug << "Status Code: " << getRequestBackHeader.statusCode << endl;
			debug << "Content-Type: " << (getRequestBackHeader.contentType.empty() ? "NULL" : getRequestBackHeader.contentType) << endl;
			debug << "Content-Length: " << (getRequestBackHeader.contentLength < 0 ? "NULL" : to_string(getRequestBackHeader.contentLength)) << endl;
			debug << "Authorization: " << (getRequestBackHeader.Authorization.empty() ? "NULL" : getRequestBackHeader.Authorization) << endl;
			debug << "User-Agent: " << (getRequestBackHeader.userAgent.empty() ? "NULL" : getRequestBackHeader.userAgent) << endl;
			debug << "Accept: " << (getRequestBackHeader.accept.empty() ? "NULL" : getRequestBackHeader.accept) << endl;
			debug << "Accept-Encoding: " << (getRequestBackHeader.acceptEncoding.empty() ? "NULL" : getRequestBackHeader.acceptEncoding) << endl;
			debug << "Accept-Language: " << (getRequestBackHeader.acceptLanguage.empty() ? "NULL" : getRequestBackHeader.acceptLanguage) << endl;
			debug << "Referer: " << (getRequestBackHeader.referer.empty() ? "NULL" : getRequestBackHeader.referer) << endl;
			debug << "Cookie: " << (getRequestBackHeader.cookie.empty() ? "NULL" : getRequestBackHeader.cookie) << endl;
			debug << "Connection: " << (getRequestBackHeader.connection.empty() ? "NULL" : getRequestBackHeader.connection) << endl;
			debug << "Cache-Control: " << (getRequestBackHeader.cacheControl.empty() ? "NULL" : getRequestBackHeader.cacheControl) << endl;
			debug << "ifModifiedSince: " << (getRequestBackHeader.ifModifiedSince.empty() ? "NULL" : getRequestBackHeader.ifModifiedSince) << endl;
			debug << "host: " << (getRequestBackHeader.host.empty() ? "NULL" : getRequestBackHeader.host) << endl;
			// 输出其他自定义头
			if (getRequestBackHeader.anotherHeader.empty()) {
				debug << "AnotherHeader: NULL" << endl;
			}
			else {
				debug << "AnotherHeader:" << endl;
				for (const auto& item : getRequestBackHeader.anotherHeader) {
					debug  << item.first<<":"<<item.second << endl;
				}
			}

			// 输出请求体
			debug << "Request Back Body: " << (getRequestBackHeader.requestBody.empty() ? "NULL" : getRequestBackHeader.requestBody) << endl;

			auto tmp = getError();
			debug << "id:" << tmp.first << endl << "Error:" << tmp.second << endl;
			debug << "--------------------------------Get debug end----------------------------------------" << endl;

			cout << debug.str();
			
		}
	public:
		bool debugMode = false;
		GetRequestHeaderStruct getRequestHeader;
		GetRequestBackStruct getRequestBackHeader;

		string SendGet(const string& url) {
			if (url.empty()) {
				requestGetError.errorId = GetRequestErrorStruct::EMPTY_URL;
				requestGetError.errorString = "URL cannot be empty";
				return "";
			}

			if (!GetParseUrl(url, parsedUrl)) return "";

			string response = sendHttpGetRequest();
			if (requestGetError.errorId != GetRequestErrorStruct::REQUEST_NO_ERROR) return "";

			parsePostRequest(response, getRequestBackHeader);

			if(debugMode==true)
			debug_mode();

			return getRequestBackHeader.requestBody;

		}

		pair<int, string> getError() {

			pair<int, string> tmp;
			tmp.first = requestGetError.errorId;
			tmp.second = requestGetError.errorString;


			cleanError();
			return tmp;
		}



	};




public:
	PostRequest postRequest;
	GetRequest getRequest;


};
