# C++ Request 库

这是一个轻量级的 C++ 库，灵感来源于 Python 的 requests 库。该库仅依赖 Windows 自带的库，并且只需一个头文件即可使用。当前版本仅支持发送 POST 请求及其响应处理，未来计划更新支持解析 POST 返回头、其他网络协议以及整合服务器功能，让 C++ 网络编程更加简单高效。

注意：目前库的功能尚不完善仅支持http将会马上支持https，在以后会被持续更新，恳请给个star。

-版本：0.1    最基本的post功能
-马上更新：
-https解析：请求头解析，keep-alive模式
-尽情期待：
-协议支持：udp，get，等服务
-高并发服务器：post服务器，udp服务器等

## 目前存在的功能

该项目提供了一个轻量级的 C++ HTTP 请求库，专注于实现 POST 请求的发送与响应处理，主要功能包括：

- **URL 解析**

  - 利用正则表达式解析输入的 URL，将其拆分为协议（HTTP/HTTPS）、主机名、端口号（如未显式指定则默认80或443）以及路径信息。
  - 该解析功能保证了后续构造 HTTP 请求时能正确提取必要的 URL 信息。

- **HTTP 请求头构造**

  - 根据解析得到的 URL 信息构造 HTTP POST 请求头。
  - 支持设置常用 HTTP 请求头字段，包括：
    - **Host**（自动附带端口号信息，如果使用非默认端口时）
    - **Content-Type**（默认值为 `application/json`）
    - **Content-Length**（自动根据请求体内容长度计算）
    - **Authorization、User-Agent、Accept、Accept-Encoding、Accept-Language、Referer、Cookie、Connection、Cache-Control** 以及其他自定义头部字段
  - 请求头与请求体之间使用空行进行分隔，符合 HTTP 协议要求。

- **POST 请求发送与响应接收**

  - 使用 Windows 自带的 Winsock 网络库来创建套接字，实现 TCP 连接。
  - 对域名进行解析后，通过指定端口与远程服务器建立连接。
  - 将构造好的完整 HTTP 请求（由请求头和请求体组成）发送给服务器。
  - 通过循环接收数据的方式获取服务器返回的响应内容，并最终将响应结果返回给调用者。

- **错误处理与反馈**

  - 内部定义了 `RequestErrorStruct` 结构体用于存储错误编号和错误描述。
  - 在各个关键操作（如 Winsock 初始化、套接字创建、域名解析、建立连接、发送和接收数据）中设置对应的错误处理逻辑。
  - 提供了 `getErrorId()` 和 `getErrorString()` 接口，便于调用者获取最近发生的错误信息，并在调用 `getErrorId()` 后自动清除错误状态。

- **配置与扩展性**

  - 提供了 `postSet()` 方法，使用户可以灵活设置或覆盖默认的 HTTP 请求头参数。

  - 项目采用了单头文件设计，使用简单，只需包含头文件即可使用，便于移动和集成到现有的 C++ 项目中。

    

# 请求头参数说明

在构造 HTTP POST 请求时，库中的 `postRequestHeader` 结构体提供了多个用于设置请求头的参数。这些参数用于控制请求的各种属性，如果参数为空，则默认不添加到请求头中。开发者可以通过直接操作 `postRequestHeader` 结构体来配置需要的请求头，或者添加其他自定义头信息到 `anotherHeader` 列表中。

## 参数列表

- **contentType**  
  类型：`string`  
  说明：指定请求体的媒体类型（例如：`application/json`）。如果为空，则不在请求头中添加该字段。

- **contentLength**  
  类型：`int`  
  说明：请求体的长度。通常自动根据请求体内容计算。如果值为默认的 0（或未设置有效长度），则不添加该字段。

- **Authorization**  
  类型：`string`  
  说明：用于携带认证信息，如令牌或密码。如果为空，则不添加此字段到请求头中。

- **userAgent**  
  类型：`string`  
  说明：定义客户端标识信息，例如 `"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`。为空时，将不会包含该字段。

- **accept**  
  类型：`string`  
  说明：指明客户端可接受的响应内容类型（如：`text/html`）。为空时不添加。

- **acceptEncoding**  
  类型：`string`  
  说明：说明客户端支持的内容编码方式（例如：`gzip, deflate`）。如果为空，则不添加。

- **acceptLanguage**  
  类型：`string`  
  说明：指定客户端可接受的自然语言（如：`en-US,en;q=0.9`）。为空时不包含此字段。

- **referer**  
  类型：`string`  
  说明：用来标示请求的来源地址。如果为空，则不会添加至请求头中。

- **cookie**  
  类型：`string`  
  说明：用于传递 Cookie 信息。如果没有设置，默认不在请求头中加入。

- **connection**  
  类型：`string`  
  说明：指定连接管理方式，如 `close` 表示请求完成后关闭连接。为空时不添加。

- **cacheControl**  
  类型：`string`  
  说明：用于设置缓存策略，例如 `no-cache`。如果未设置，将不会包含在请求头中。

- **anotherHeader**  
  类型：`list<string>`  
  说明：用于添加其他自定义请求头。开发者可以通过该列表手动添加一些不在上述默认字段列表中的请求头。

## 特性

- **轻量级**：仅包含一个头文件，集成简单。
- **依赖内置库**：仅使用 Windows 自带的库，无需额外依赖。
- **基本的 POST 支持**：当前版本支持 POST 请求的发送与接收。
- **未来扩展**：
  - 解析 POST 请求返回的头部信息。
  - 扩展其他常用网络协议。
  - 整合服务器端功能，实现更加便捷的使用方式。

## 示例代码

以下代码展示了如何使用该库发送 POST 请求，并获取返回结果及错误信息：

```cpp
#include <iostream>
// 包含你的头文件（假设文件名为 request.h）
#include "request.h"

using namespace std;

int main() {
    // 创建一个 request 实例
    request chatGpt;

    // 设置请求头：Content-Type
    chatGpt.postRequestHeader.contentType = "application/json";

    // 设置目标 URL
    chatGpt.setUrl("http://127.0.0.1:8585/v1/chat/completions");

    // 使用 SendPost() 发送 POST 请求，传入 JSON 字符串参数
    cout << "return: " << chatGpt.SendPost(u8"{\"model\": \"70b@q8_0\",\"prompt\" : \"Once upon a time\",\"messages\": [ { \"role\": \"user\", \"content\" : \"\" } ],\"max_tokens\" : 50,\"temperature\" : 0.7}") << endl;
    
    // 输出错误码和错误描述（若有）
    cout << "id: " << chatGpt.getErrorId() << endl;
    cout << "error: " << chatGpt.getErrorString() << endl;

    return 0;
}
```
