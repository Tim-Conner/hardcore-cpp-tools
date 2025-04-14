//##############################
//版本：0.1
//作者：TimConner
//上传时间：2025/4/14 12：47
//##############################
#pragma once
#include <iostream>
#include <string>
#include <winsock2.h>
#include <list>
#include <ws2tcpip.h>
#include <sstream>
#include <regex>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

class request {
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

        if (getaddrinfo(parsed.hostname.c_str(), std::to_string(parsed.port).c_str(), &hints, &result) != 0) {
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
        cout << "send:" << endl << requestBodySend << endl;
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
        requestStream << "POST " << parsed.path << " HTTP/1.1\r\n";

        // Host头：包括主机名和必要时端口号
        if (!parsed.hostname.empty()) {
            requestStream << "Host: " << parsed.hostname;
            if (parsed.port != 80 && parsed.port != 443) { // 非默认端口需显示指定
                requestStream << ":" << parsed.port;
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

public:
    ParsedUrl parsed;                // 解析后的URL数据
    PostRequestStruct postRequestHeader; // POST请求使用的头信息和请求体

    // 构造函数，设置默认的请求头参数
    request() {
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
    int getErrorId() {
        int tmp = requestError.errorId;
        cleanError();
        return tmp;
    }
    
    // 获取错误描述
    string getErrorString() {
        return requestError.errorString;
    }

    // POST请求相关头信息设置函数
    int postSet(std::string contentType = "",
                int contentLength = 0,
                std::string Authorization = "",
                std::string userAgent = "",
                std::string accept = "",
                std::string acceptEncoding = "",
                std::string acceptLanguage = "",
                std::string referer = "",
                std::string cookie = "",
                std::string connection = "",
                std::string cacheControl = "") {
        if (!contentType.empty()) {
            postRequestHeader.contentType = contentType;
        }
        if (contentLength != 0) {
            postRequestHeader.contentLength = contentLength;
        }
        if (!Authorization.empty()) {
            postRequestHeader.Authorization = Authorization;
        }
        if (!userAgent.empty()) {
            postRequestHeader.userAgent = userAgent;
        }
        if (!accept.empty()) {
            postRequestHeader.accept = accept;
        }
        if (!acceptEncoding.empty()) {
            postRequestHeader.acceptEncoding = acceptEncoding;
        }
        if (!acceptLanguage.empty()) {
            postRequestHeader.acceptLanguage = acceptLanguage;
        }
        if (!referer.empty()) {
            postRequestHeader.referer = referer;
        }
        if (!cookie.empty()) {
            postRequestHeader.cookie = cookie;
        }
        if (!connection.empty()) {
            postRequestHeader.connection = connection;
        }
        if (!cacheControl.empty()) {
            postRequestHeader.cacheControl = cacheControl;
        }
        return 0;
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
        if (!parseUrl(request_Url, parsed)) {
            requestError.errorId = 100;
            requestError.errorString = "Invalid URL format";
            return "";
        }
       
        // 构造完整的HTTP请求字符串（请求头 + 请求体）
        string mainRequest = makePostHeader() + postRequestHeader.requestBody;
        return sendHttpPostRequest(mainRequest);
    }
};
