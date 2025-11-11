#define _WIN32_WINNT 0x0600   // has to be before windows headers
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#ifndef WINHTTP_AUTH_BASIC
#define WINHTTP_AUTH_BASIC 0x00000001
#endif

#include "http.h"            // http header after the windows headers

#define URLPATH_SIZE 1024

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <regex>
#include <memory>
#include <cstdint> 
#include <chrono>
#include <thread> 
#include <locale>
#include <codecvt>
#include <fstream>
#include <algorithm>


#include "../headers/wide.h"

#define ANSI_BLACK         "\x1b[30m"
#define ANSI_RED           "\x1b[31m"
#define ANSI_GREEN         "\x1b[32m"
#define ANSI_YELLOW        "\x1b[33m"
#define ANSI_BLUE          "\x1b[34m"
#define ANSI_MAGENTA       "\x1b[35m"
#define ANSI_CYAN          "\x1b[36m"
#define ANSI_WHITE         "\x1b[37m"
#define ANSI_RESET         "\x1b[0m"

#define ANSI_BOLD_BLACK    "\x1b[1;30m"
#define ANSI_BOLD_RED      "\x1b[1;31m"
#define ANSI_BOLD_GREEN    "\x1b[1;32m"
#define ANSI_BOLD_YELLOW   "\x1b[1;33m"
#define ANSI_BOLD_BLUE     "\x1b[1;34m"
#define ANSI_BOLD_MAGENTA  "\x1b[1;35m"
#define ANSI_BOLD_CYAN     "\x1b[1;36m"
#define ANSI_BOLD_WHITE    "\x1b[1;37m"
#define ANSI_BOLD          "\x1b[1m"

std::vector<uint8_t> ToUtf8Bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

void CmdHttpPut(const std::string& args) {
    std::vector<std::string> tokens;
    {
        std::istringstream iss(args);
        std::string token;
        while (std::getline(iss, token, '|')) {
            size_t start = token.find_first_not_of(" \t");
            size_t end = token.find_last_not_of(" \t");
            if (start != std::string::npos && end != std::string::npos)
                tokens.push_back(token.substr(start, end - start + 1));
        }
    }

    if (tokens.empty()) {
        std::cerr << "Usage: put <URL> [header1|header2|...] [|payload]\n";
        return;
    }

    std::string url = tokens[0];
    std::vector<std::string> headers;
    std::string payload;

    if (tokens.size() > 1) {
        if (tokens.size() > 2) {
            for (size_t i = 1; i < tokens.size() - 1; ++i)
                headers.push_back(tokens[i]);
            payload = tokens.back();
        } else {
            if (tokens[1].find(':') != std::string::npos)
                headers.push_back(tokens[1]);
            else
                payload = tokens[1];
        }
    }

    std::wstring wurl = ConvertStringToWString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};

    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = (DWORD)_countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = (DWORD)_countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    if (urlComp.nScheme != INTERNET_SCHEME_HTTP && urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        std::cerr << "Unsupported URL scheme. Only HTTP and HTTPS are supported.\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession,
                                       host,
                                       urlComp.nPort,
                                       0);
    if (!hConnect) {
        std::cerr << "Failed to connect to host. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                           L"PUT",
                                           path,
                                           nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           dwFlags);
    if (!hRequest) {
        std::cerr << "Failed to open HTTP request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy))) {
        std::cerr << "Failed to set redirect policy. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring headers_w;
    for (const auto& hdr : headers) {
        headers_w += ConvertStringToWString(hdr) + L"\r\n";
    }
    const wchar_t* additionalHeaders = headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str();
    DWORD headersLength = (DWORD)headers_w.length();

    const char* payloadData = nullptr;
    DWORD payloadSize = 0;
    std::vector<char> payloadBuffer;
    if (!payload.empty()) {
        payloadBuffer.assign(payload.begin(), payload.end());
        payloadData = payloadBuffer.data();
        payloadSize = (DWORD)payloadBuffer.size();
    }

    if (!WinHttpSendRequest(hRequest,
                           additionalHeaders,
                           headersLength,
                           (void*)payloadData,
                           payloadSize,
                           payloadSize,
                           0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             nullptr, &statusCode, &size, nullptr)) {
        std::cerr << "Failed to query status code. Error: " << GetLastError() << "\n";
    } else {
        std::cout << "HTTP Status Code: " << statusCode << "\n\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            std::cerr << "Error querying data availability: " << GetLastError() << "\n";
            break;
        }
        if (dwSize == 0)
            break;

        std::vector<char> buffer(dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
            std::cerr << "Error reading data: " << GetLastError() << "\n";
            break;
        }
        buffer[dwDownloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

struct WinHttpHandle {
    HINTERNET handle = nullptr;

    WinHttpHandle() = default;

    explicit WinHttpHandle(HINTERNET h) : handle(h) {}

    ~WinHttpHandle() {
        if (handle) WinHttpCloseHandle(handle);
    }

    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    WinHttpHandle(WinHttpHandle&& other) noexcept : handle(other.handle) {
        other.handle = nullptr;
    }

    WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
        static_assert(std::is_same_v<decltype(other), WinHttpHandle&&>, "other is not WinHttpHandle&&");
        if (this != std::addressof(other)) {
            if (handle) WinHttpCloseHandle(handle);
            handle = other.handle;
            other.handle = nullptr;
        }
        return *this;
    }

    explicit operator bool() const { return handle != nullptr; }
    HINTERNET* operator&() { return &handle; }
    HINTERNET get() const { return handle; }
};

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return {};
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

static bool ParseArgs(const std::string& args, std::string& outUrl, std::vector<std::string>& outHeaders) {
    std::istringstream iss(args);
    if (!(iss >> outUrl)) return false; 

    std::string header;
    while (std::getline(iss, header, '|')) {
        size_t start = header.find_first_not_of(" \t");
        size_t end = header.find_last_not_of(" \t");
        if (start != std::string::npos && end != std::string::npos)
            outHeaders.push_back(header.substr(start, end - start + 1));
    }
    return true;
}

void CmdHttpGet(const std::string& args) {
    std::string url;
    std::vector<std::string> headers;
    std::string cookieJarFile;

    std::istringstream iss(args);
    std::string token;
    while (iss >> token) {
        if (token == "--cookie-jar") {
            if (!(iss >> cookieJarFile)) {
                std::cerr << "Missing filename after --cookie-jar\n";
                return;
            }
        } else if (url.empty()) {
            url = token;
        } else {
            headers.push_back(token);
        }
    }

    if (url.empty()) {
        std::cerr << "Usage: get <URL> [header1|header2|...] [--cookie-jar file]\n";
        return;
    }

    WinHttpHandle hSession;
    hSession.handle = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session. Error: " << GetLastError() << "\n";
        return;
    }

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    std::wstring wurl = StringToWString(url);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    if (urlComp.nScheme != INTERNET_SCHEME_HTTP && urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        std::cerr << "Unsupported URL scheme. Only HTTP and HTTPS are supported.\n";
        return;
    }

    WinHttpHandle hConnect;
    hConnect.handle = WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cerr << "Failed to connect to host. Error: " << GetLastError() << "\n";
        return;
    }

    DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    WinHttpHandle hRequest;
    hRequest.handle = WinHttpOpenRequest(hConnect.get(), L"GET", urlComp.lpszUrlPath,
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest) {
        std::cerr << "Failed to open HTTP request. Error: " << GetLastError() << "\n";
        return;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    // Load and apply cookie header from file if exists
    if (!cookieJarFile.empty()) {
        std::ifstream cookieFile(cookieJarFile);
        if (cookieFile) {
            std::string cookieLine((std::istreambuf_iterator<char>(cookieFile)), {});
            std::wstring wcookie = StringToWString("Cookie: " + cookieLine);
            WinHttpAddRequestHeaders(hRequest.get(), wcookie.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
        }
    }

    std::wstring headers_w;
    for (const auto& hdr : headers) {
        headers_w += StringToWString(hdr) + L"\r\n";
    }

    if (!WinHttpSendRequest(hRequest.get(),
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(),
                            nullptr, 0, 0, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        return;
    }

    if (!WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n\n";
    }

    if (!cookieJarFile.empty()) {
        DWORD dwSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &dwSize, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t));
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, buffer.data(), &dwSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wstring cookies(buffer.data());
                std::string cookieStr = WStringToString(cookies);
                std::ofstream out(cookieJarFile, std::ios::trunc);
                out << cookieStr << "\n";
            }
        }
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest.get(), &dwSize)) {
            std::cerr << "Error querying data availability: " << GetLastError() << "\n";
            break;
        }
        if (dwSize == 0) break;

        std::vector<char> buffer(dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest.get(), buffer.data(), dwSize, &dwDownloaded)) {
            std::cerr << "Error reading data: " << GetLastError() << "\n";
            break;
        }
        buffer[dwDownloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;
}

std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    size_t end = s.find_last_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

void CmdHttpPost(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);  
        }
        tokens.push_back(token);
    }

    std::string url, body;
    std::vector<std::wstring> headers;
    std::wstring contentTypeOverride;

    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (token == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (token == "-T" && i + 1 < tokens.size()) {
            contentTypeOverride = ToWString(tokens[++i]);
        } else if (token == "-d" && i + 1 < tokens.size()) {
            body = tokens[++i];
        } else if (token.rfind("-", 0) != 0 && url.empty()) {
            url = Trim(token);
        }
    }

    if (url.empty() || body.empty()) {
        std::cout << "Error:\nError: Usage: post [-H \"Header\"] [-T content-type] -d <body> <url>\n";
        return;
    }

    std::wstring finalContentType;
    if (!contentTypeOverride.empty()) {
        finalContentType = L"Content-Type: " + contentTypeOverride + L"\r\n";
    } else if (!body.empty() && (body[0] == '{' || body[0] == '[')) {
        finalContentType = L"Content-Type: application/json\r\n";
    } else {
        finalContentType = L"Content-Type: application/x-www-form-urlencoded\r\n";
    }
    headers.insert(headers.begin(), finalContentType);

    std::wstring wurl = ToWString(url);
    std::wcout << L"Debug: URL = " << wurl << L"\n";

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.c_str(), (DWORD)allHeaders.length(),
                                       (LPVOID)body.data(), (DWORD)body.size(),
                                       (DWORD)body.size(), 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cout << "Success:\nResponse:\n";

        DWORD dwSize = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                std::cout << "Error: Failed to query data available.\n";
                break;
            }
            if (dwSize == 0) {
                break; 
            }

            std::vector<char> buffer(dwSize + 1, 0);
            DWORD dwDownloaded = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                std::cout << "Error: Failed to read data.\n";
                break;
            }

            std::cout << std::string(buffer.data(), dwDownloaded);
        } while (dwSize > 0);

        std::cout << std::endl;

    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nError: HTTP POST failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpHeader(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (tokens[i].rfind("-", 0) != 0 && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: head [-H \"Header\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)allHeaders.length(),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   WINHTTP_HEADER_NAME_BY_INDEX, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Success:\nResponse headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nError: Failed to read response headers\n";
            }
        } else {
            std::cout << "Error:\nError: Failed to query response headers size\n";
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nError: HTTP HEAD failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpDelete(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (tokens[i].rfind("-", 0) != 0 && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: delete [-H \"Header\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"DELETE", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)allHeaders.length(),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                nullptr, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
            std::cout << "Success:\nHTTP DELETE status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP DELETE request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   WINHTTP_HEADER_NAME_BY_INDEX, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP DELETE failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpPatch(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;
    std::string body;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (tokens[i] == "-d" && i + 1 < tokens.size()) {
            body = tokens[++i];
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: patch [-H \"Header\"] [-d \"body\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"PATCH", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    std::vector<uint8_t> bodyBytes = ToUtf8Bytes(body);

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)(allHeaders.size() * sizeof(wchar_t)),
                                       bodyBytes.empty() ? nullptr : bodyBytes.data(),
                                       (DWORD)bodyBytes.size(),
                                       (DWORD)bodyBytes.size(),
                                       0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
            std::cout << "Success:\nHTTP PATCH status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP PATCH request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP PATCH failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpOptions(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(ToWString(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nError: Usage: options [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = ToWString(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nError: Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nError: Invalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nError: Connection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"OPTIONS", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::cout << "Error:\nError: Failed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)(allHeaders.size()),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP OPTIONS status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP OPTIONS request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP OPTIONS failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

bool ParseUrl(const std::wstring& url, URL_COMPONENTS& urlComp) {
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    static wchar_t host[256];
    static wchar_t path[1024];
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    return WinHttpCrackUrl(url.c_str(), (DWORD)-1, 0, &urlComp) != FALSE;
}

void CmdHttpLink(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: link [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE) : WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"LINK", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           flags);
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest,
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)(allHeaders.size()),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP LINK status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP LINK request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP LINK failed (code " << error << ")\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpUnlink(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: unlink [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        return;
    }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"UNLINK", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        return;
    }

    std::wstring allHeaders;
    for (const auto& h : headers) {
        allHeaders += h + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest.get(),
                                       allHeaders.empty() ? nullptr : allHeaders.c_str(),
                                       (DWORD)allHeaders.size(),
                                       nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP UNLINK status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP UNLINK request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP UNLINK failed (code " << error << ")\n";
    }
}

void CmdHttpTrace(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    auto begin = std::sregex_iterator(args.begin(), args.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.length() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: trace [-H \"Header: value\"] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) {
        std::cout << "Error:\nFailed to open WinHTTP session\n";
        return;
    }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) {
        std::cout << "Error:\nConnection failed\n";
        return;
    }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"TRACE", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) {
        std::cout << "Error:\nFailed to open request\n";
        return;
    }

    for (const auto& h : headers) {
        if (!WinHttpAddRequestHeaders(hRequest.get(), h.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cout << "Error:\nFailed to add header: " << WideToUtf8(h) << "\n";
            return;
        }
    }

    BOOL bResults = WinHttpSendRequest(
        hRequest.get(),
        nullptr,
        0,
        nullptr, 0, 0, 0);

    if (bResults && WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP TRACE status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP TRACE request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                           nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }
    } else {
        DWORD error = GetLastError();
        std::cout << "Error:\nHTTP TRACE failed (code " << error << ")\n";
    }
}

std::vector<std::wstring> ParseHeaders(const std::vector<std::string>& headerArgs) {
    std::vector<std::wstring> headers;
    for (const auto& h : headerArgs) {
        headers.push_back(NormalStringToWideString(h));
    }
    return headers;
}

void PrintWinHttpError(const std::string& context) {
    DWORD err = GetLastError();
    std::cerr << context << " failed with error: " << err << std::endl;
}

static HINTERNET g_hSession = nullptr;
static HINTERNET g_hConnect = nullptr;
static HINTERNET g_hRequest = nullptr;

void CmdHttpConnect(const std::string& args) {
    if (args == "exit") {
        if (g_hRequest) {
            WinHttpCloseHandle(g_hRequest);
            g_hRequest = nullptr;
        }
        if (g_hConnect) {
            WinHttpCloseHandle(g_hConnect);
            g_hConnect = nullptr;
        }
        if (g_hSession) {
            WinHttpCloseHandle(g_hSession);
            g_hSession = nullptr;
        }
        std::cout << "Connection tunnel closed." << std::endl;
        return;
    }

    if (g_hRequest) {
        WinHttpCloseHandle(g_hRequest);
        g_hRequest = nullptr;
    }
    if (g_hConnect) {
        WinHttpCloseHandle(g_hConnect);
        g_hConnect = nullptr;
    }
    if (g_hSession) {
        WinHttpCloseHandle(g_hSession);
        g_hSession = nullptr;
    }

    std::istringstream iss(args);
    std::string proxy, target;

    iss >> proxy >> target;
    if (proxy.empty() || target.empty()) {
        std::cout << "Usage: connect <proxyHost:port> <targetHost:port> [-H \"Header: value\" ...]\n";
        return;
    }

    std::vector<std::string> headersArgs;
    while (iss >> std::ws) {
        if (iss.peek() == '-') {
            std::string flag;
            iss >> flag;
            if (flag == "-H") {
                std::string headerVal;
                if (!(iss >> std::quoted(headerVal))) {
                    std::cout << "Invalid header format. Use -H \"Header: value\"\n";
                    return;
                }
                headersArgs.push_back(headerVal);
            } else {
                std::cout << "Unknown flag " << flag << "\n";
                return;
            }
        } else {
            break;
        }
    }

    size_t colonPos = target.find(':');
    if (colonPos == std::string::npos) {
        std::cout << "Invalid target format, must be host:port\n";
        return;
    }

    std::string targetHost = target.substr(0, colonPos);
    std::string targetPortStr = target.substr(colonPos + 1);
    int targetPort = 0;
    try {
        targetPort = std::stoi(targetPortStr);
    } catch (...) {
        std::cout << "Invalid target port\n";
        return;
    }
    if (targetPort <= 0 || targetPort > 65535) {
        std::cout << "Invalid target port\n";
        return;
    }

    std::wstring wProxy = NormalStringToWideString("http=" + proxy);
    std::wstring wTargetHost = NormalStringToWideString(targetHost);

    g_hSession = WinHttpOpen(L"Zephyr/1.0",
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        wProxy.c_str(),
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_hSession) {
        PrintWinHttpError("WinHttpOpen");
        return;
    }

    g_hConnect = WinHttpConnect(g_hSession, wTargetHost.c_str(), targetPort, 0);
    if (!g_hConnect) {
        PrintWinHttpError("WinHttpConnect");
        WinHttpCloseHandle(g_hSession);
        g_hSession = nullptr;
        return;
    }

    g_hRequest = WinHttpOpenRequest(g_hConnect, L"GET", nullptr,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!g_hRequest) {
        PrintWinHttpError("WinHttpOpenRequest");
        WinHttpCloseHandle(g_hConnect);
        WinHttpCloseHandle(g_hSession);
        g_hConnect = nullptr;
        g_hSession = nullptr;
        return;
    }

    for (const auto& hdr : ParseHeaders(headersArgs)) {
        if (!WinHttpAddRequestHeaders(g_hRequest, hdr.c_str(),
            static_cast<DWORD>(hdr.length()),
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            PrintWinHttpError("WinHttpAddRequestHeaders");
        }
    }

    BOOL bSend = WinHttpSendRequest(g_hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        nullptr, 0, 0, 0);
    if (!bSend) {
        PrintWinHttpError("WinHttpSendRequest");
        WinHttpCloseHandle(g_hRequest);
        WinHttpCloseHandle(g_hConnect);
        WinHttpCloseHandle(g_hSession);
        g_hRequest = nullptr;
        g_hConnect = nullptr;
        g_hSession = nullptr;
        return;
    }

    if (!WinHttpReceiveResponse(g_hRequest, nullptr)) {
        PrintWinHttpError("WinHttpReceiveResponse");
        WinHttpCloseHandle(g_hRequest);
        WinHttpCloseHandle(g_hConnect);
        WinHttpCloseHandle(g_hSession);
        g_hRequest = nullptr;
        g_hConnect = nullptr;
        g_hSession = nullptr;
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(g_hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        nullptr, &statusCode, &size, nullptr)) {
        PrintWinHttpError("WinHttpQueryHeaders");
    }

    std::cout << "HTTPS request status code: " << statusCode << std::endl;
    if (statusCode == 200) {
        std::cout << "Successfully connected to " << target << " through proxy " << proxy << std::endl;
    } else {
        std::cout << "Failed HTTPS request, status code: " << statusCode << std::endl;
    }

}

void CmdHttpPropFind(const std::string& args) {
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    for (auto it = std::sregex_iterator(args.begin(), args.end(), re);
         it != std::sregex_iterator(); ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.size() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;
    std::wstring depth = L"0"; // default depth

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (tokens[i] == "--depth" && i + 1 < tokens.size()) {
            std::string d = tokens[++i];
            if (d == "0" || d == "1" || d == "infinity") {
                depth = StringToWide(d);
            } else {
                std::cout << "Error:\n--depth must be 0, 1, or infinity\n";
                return;
            }
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: propfind [-H \"Header: value\"] [--depth 0|1|infinity] <url>\n";
        return;
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) { std::cout << "Error:\nFailed to open WinHTTP session\n"; return; }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) { std::cout << "Error:\nConnection failed\n"; return; }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"PROPFIND", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { std::cout << "Error:\nFailed to open request\n"; return; }

    // Add depth header
    headers.push_back(L"Depth: " + depth);

    // Ensure Content-Type header
    bool hasContentType = false;
    for (const auto& h : headers) {
        if (_wcsnicmp(h.c_str(), L"Content-Type:", 13) == 0) { hasContentType = true; break; }
    }
    if (!hasContentType) headers.push_back(L"Content-Type: application/xml");

    for (const auto& h : headers) {
        if (!WinHttpAddRequestHeaders(hRequest.get(), h.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cout << "Error:\nFailed to add header: " << WideToUtf8(h) << "\n";
            return;
        }
    }

    const char* propfindXml =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<propfind xmlns=\"DAV:\">"
        "<allprop/>"
        "</propfind>";
    DWORD bodySize = (DWORD)strlen(propfindXml);

    if (WinHttpSendRequest(hRequest.get(), nullptr, 0, (LPVOID)propfindXml, bodySize, bodySize, 0) &&
        WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        
        DWORD statusCode = 0, statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP PROPFIND status code: " << statusCode << "\n";
        } else {
            std::cout << "Success:\nHTTP PROPFIND request sent, but failed to get status code\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF, nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            } else {
                std::cout << "Error:\nFailed to read response headers\n";
            }
        }

        std::vector<char> buffer(4096);
        DWORD bytesRead = 0;
        std::cout << "Response body:\n";
        while (WinHttpReadData(hRequest.get(), buffer.data(), (DWORD)buffer.size(), &bytesRead) && bytesRead > 0) {
            std::cout.write(buffer.data(), bytesRead);
        }
        std::cout << "\n";
    } else {
        std::cout << "Error:\nHTTP PROPFIND failed (code " << GetLastError() << ")\n";
    }
}

void CmdHttpPropPatch(const std::string& args) {
    // Tokenize arguments
    std::vector<std::string> tokens;
    std::regex re(R"((\"([^\"\\]|\\.)*\"|\S+))");
    for (auto it = std::sregex_iterator(args.begin(), args.end(), re);
         it != std::sregex_iterator(); ++it) {
        std::string token = (*it)[1].str();
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.size() - 2);
        }
        tokens.push_back(token);
    }

    std::string url;
    std::vector<std::wstring> headers;
    std::wstring depth = L"0"; // default
    std::string xmlBody;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(StringToWide(tokens[++i]));
        } else if (tokens[i] == "--depth" && i + 1 < tokens.size()) {
            std::string d = tokens[++i];
            if (d == "0" || d == "1" || d == "infinity") {
                depth = StringToWide(d);
            } else {
                std::cout << "Error:\n--depth must be 0, 1, or infinity\n";
                return;
            }
        } else if (tokens[i] == "-X" && i + 1 < tokens.size()) {
            if (tokens[++i] != "PROPPATCH") {
                std::cout << "Warning: Using non-standard method\n";
            }
        } else if (tokens[i] == "-d" && i + 1 < tokens.size()) {
            xmlBody = tokens[++i];
        } else if (!tokens[i].empty() && tokens[i][0] != '-' && url.empty()) {
            url = tokens[i];
        }
    }

    if (url.empty()) {
        std::cout << "Error:\nUsage: proppatch [-H \"Header: value\"] [--depth 0|1|infinity] -d \"<xml>\" <url>\n";
        return;
    }

    if (xmlBody.empty()) {
        xmlBody =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<propertyupdate xmlns=\"DAV:\">"
            "<set><prop><example:customProperty xmlns:example=\"http://example.com/\">value</example:customProperty></prop></set>"
            "</propertyupdate>";
    }

    std::wstring wurl = StringToWide(url);

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256] = { 0 };
    wchar_t path[1024] = { 0 };
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)-1, 0, &urlComp)) {
        std::cout << "Error:\nInvalid URL\n";
        return;
    }

    WinHttpHandle hSession(WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) { std::cout << "Error:\nFailed to open WinHTTP session\n"; return; }

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
    if (!hConnect) { std::cout << "Error:\nConnection failed\n"; return; }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"PROPPATCH", urlComp.lpszUrlPath,
                                             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { std::cout << "Error:\nFailed to open request\n"; return; }

    headers.push_back(L"Depth: " + depth);
    bool hasContentType = false;
    for (const auto& h : headers) {
        if (_wcsnicmp(h.c_str(), L"Content-Type:", 13) == 0) { hasContentType = true; break; }
    }
    if (!hasContentType) headers.push_back(L"Content-Type: application/xml");

    for (const auto& h : headers) {
        if (!WinHttpAddRequestHeaders(hRequest.get(), h.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cout << "Error:\nFailed to add header: " << WideToUtf8(h) << "\n";
            return;
        }
    }

    DWORD bodySize = (DWORD)xmlBody.size();

    if (WinHttpSendRequest(hRequest.get(), nullptr, 0, (LPVOID)xmlBody.c_str(), bodySize, bodySize, 0) &&
        WinHttpReceiveResponse(hRequest.get(), nullptr)) {

        DWORD statusCode = 0, statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr)) {
            std::cout << "Success:\nHTTP PROPPATCH status code: " << statusCode << "\n";
        }

        DWORD headersSize = 0;
        WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF, nullptr, nullptr, &headersSize, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::wstring headersStr(headersSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   nullptr, &headersStr[0], &headersSize, WINHTTP_NO_HEADER_INDEX)) {
                std::wcout << L"Response headers:\n" << headersStr << L"\n";
            }
        }

        std::vector<char> buffer(4096);
        DWORD bytesRead = 0;
        std::cout << "Response body:\n";
        while (WinHttpReadData(hRequest.get(), buffer.data(), (DWORD)buffer.size(), &bytesRead) && bytesRead > 0) {
            std::cout.write(buffer.data(), bytesRead);
        }
        std::cout << "\n";
    } else {
        std::cout << "Error:\nHTTP PROPPATCH failed (code " << GetLastError() << ")\n";
    }
}

bool URLParser(const std::string& url, std::wstring& outHost, std::wstring& outPath, INTERNET_PORT& outPort, bool& useHttps) {
    size_t pos = url.find("://");
    if (pos == std::string::npos) return false;

    std::string protocol = url.substr(0, pos);
    std::string rest = url.substr(pos + 3);

    useHttps = (protocol == "https");

    size_t slashPos = rest.find('/');
    std::string host;
    std::string path;
    if (slashPos == std::string::npos) {
        host = rest;
        path = "/";
    } else {
        host = rest.substr(0, slashPos);
        path = rest.substr(slashPos);
    }

    size_t colonPos = host.find(':');
    if (colonPos != std::string::npos) {
        outPort = static_cast<INTERNET_PORT>(std::stoi(host.substr(colonPos + 1)));
        host = host.substr(0, colonPos);
    } else {
        outPort = useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), (int)host.length(), nullptr, 0);
    outHost.resize(size_needed);
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), (int)host.length(), &outHost[0], size_needed);

    size_needed = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.length(), nullptr, 0);
    outPath.resize(size_needed);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.length(), &outPath[0], size_needed);

    return true;
}

void PrintWindowsHttpError(const std::string& context) {
    DWORD err = GetLastError();
    std::cerr << context << " failed with error: " << err << std::endl;
}

void CmdHttpDownload(const std::string& args) {
    std::istringstream iss(args);
    std::string url, outputFile;

    iss >> url >> outputFile;
    if (url.empty() || outputFile.empty()) {
        std::cout << "Usage: download <url> <output_file>\n";
        return;
    }

    std::wstring wHost, wPath;
    INTERNET_PORT port = 0;
    bool useHttps = false;

    if (!URLParser(url, wHost, wPath, port, useHttps)) {
        std::cout << "Invalid URL\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS,
                                    0);
    if (!hSession) {
        PrintWindowsHttpError("WinHttpOpen");
        return;
    }

    DWORD dwSecureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(
            hSession,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            &dwSecureProtocols,
            sizeof(dwSecureProtocols))) 
    {
        PrintWindowsHttpError("WinHttpSetOption (TLS protocols)");
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) {
        PrintWindowsHttpError("WinHttpConnect");
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD dwFlags = useHttps ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(),
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           dwFlags);
    if (!hRequest) {
        PrintWindowsHttpError("WinHttpOpenRequest");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            nullptr, 0, 0, 0)) {
        PrintWindowsHttpError("WinHttpSendRequest");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        PrintWindowsHttpError("WinHttpReceiveResponse");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             nullptr, &statusCode, &size, nullptr)) {
        PrintWindowsHttpError("WinHttpQueryHeaders");
    }

    if (statusCode != 200) {
        std::cout << "HTTP request failed, status code: " << statusCode << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::ofstream outfile(outputFile, std::ios::binary);
    if (!outfile) {
        std::cout << "Failed to open output file: " << outputFile << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    const int bufSize = 8192;
    char buffer[bufSize];
    DWORD bytesAvailable = 0, bytesRead = 0;

    while (true) {
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
            PrintWindowsHttpError("WinHttpQueryDataAvailable");
            break;
        }
        if (bytesAvailable == 0)
            break;

        DWORD toRead = (bytesAvailable < bufSize) ? bytesAvailable : bufSize;

        if (!WinHttpReadData(hRequest, buffer, toRead, &bytesRead)) {
            PrintWindowsHttpError("WinHttpReadData");
            break;
        }
        if (bytesRead == 0)
            break;

        outfile.write(buffer, bytesRead);
        if (!outfile) {
            std::cout << "Error writing to file\n";
            break;
        }
    }

    std::cout << "File downloaded successfully to " << outputFile << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpPurge(const std::string& args) {
    std::vector<std::string> tokens;
    {
        std::istringstream iss(args);
        std::string token;
        while (std::getline(iss, token, '|')) {
            size_t start = token.find_first_not_of(" \t");
            size_t end = token.find_last_not_of(" \t");
            if (start != std::string::npos && end != std::string::npos)
                tokens.push_back(token.substr(start, end - start + 1));
        }
    }

    if (tokens.empty()) {
        std::cerr << "Usage: purge <URL> [header1|header2|...] [|payload]\n";
        return;
    }

    std::string url = tokens[0];
    std::vector<std::string> headers;
    std::string payload;

    if (tokens.size() > 1) {
        if (tokens.size() > 2) {
            for (size_t i = 1; i < tokens.size() - 1; ++i)
                headers.push_back(tokens[i]);
            payload = tokens.back();
        } else {
            if (tokens[1].find(':') != std::string::npos)
                headers.push_back(tokens[1]);
            else
                payload = tokens[1];
        }
    }

    std::wstring wurl = ToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};

    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    if (urlComp.nScheme != INTERNET_SCHEME_HTTP && urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        std::cerr << "Unsupported URL scheme. Only HTTP and HTTPS are supported.\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession,
                                        host,
                                        urlComp.nPort,
                                        0);
    if (!hConnect) {
        std::cerr << "Failed to connect to host. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD dwFlags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                            L"PURGE",
                                            path,
                                            nullptr,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            dwFlags);
    if (!hRequest) {
        std::cerr << "Failed to open HTTP request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    std::wstring headers_w;
    for (size_t i = 0; i < headers.size(); ++i) {
        headers_w += ToWideString(headers[i]);
        headers_w += L"\r\n";
    }

    std::vector<char> payloadBuffer;
    const char* payloadData = nullptr;
    DWORD payloadSize = 0;
    if (!payload.empty()) {
        payloadBuffer.assign(payload.begin(), payload.end());
        payloadData = payloadBuffer.data();
        payloadSize = (DWORD)payloadBuffer.size();

        headers_w += L"Content-Length: " + std::to_wstring(payloadSize) + L"\r\n";
    }

    if (!headers_w.empty()) {
        headers_w += L"\r\n";
    }

    const wchar_t* additionalHeaders = headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str();
    DWORD headersLength = (DWORD)headers_w.length();

    if (!WinHttpSendRequest(hRequest,
                            additionalHeaders,
                            headersLength,
                            (void*)payloadData,
                            payloadSize,
                            payloadSize,
                            0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        const char* color = nullptr;
        if (statusCode == 200) {
            color = ANSI_BOLD_GREEN;
        } else if ((statusCode >= 200 && statusCode < 300) || (statusCode >= 300 && statusCode < 400)) {
            color = ANSI_BOLD_YELLOW;
        } else {
            color = ANSI_BOLD_RED;
        }
        std::cout << color << "HTTP Status Code: " << statusCode << ANSI_RESET << "\n\n";
    } else {
        std::cerr << "Failed to query status code. Error: " << GetLastError() << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            std::cerr << "Error querying data availability: " << GetLastError() << "\n";
            break;
        }
        if (dwSize == 0)
            break;

        std::vector<char> buffer(dwSize + 1);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
            std::cerr << "Error reading data: " << GetLastError() << "\n";
            break;
        }
        buffer[dwDownloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpReport(const std::string& args) {
    std::vector<std::string> tokens;
    std::istringstream iss(args);
    std::string token;
    bool inQuotes = false;
    std::string temp;

    // Split arguments respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: REPORT [-H \"Header: value\"] [-D depth] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;
    int depth = -1;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (tokens[i] == "-D" && i + 1 < tokens.size()) {
            depth = std::stoi(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            // Combine rest of tokens as body (with spaces)
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"REPORT", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    if (depth >= 0) headers.push_back("Depth: " + std::to_string(depth));

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(), (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpMkcol(const std::string& args) {
    std::vector<std::string> tokens;
    std::istringstream iss(args);
    std::string token;
    bool inQuotes = false;
    std::string temp;

    // Split arguments respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: MKCOL [-H \"Header: value\"] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            // Combine rest of tokens as body
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"MKCOL", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(), (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpBind(const std::string& args) {
    std::vector<std::string> tokens;
    std::istringstream iss(args);
    std::string token;
    bool inQuotes = false;
    std::string temp;

    // Split args respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: BIND [-H \"Header: value\"] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            // Remaining tokens = request body
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"BIND", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
        if (headers_w.find(L"Content-Type:") == std::wstring::npos)
            headers_w += L"Content-Type: text/xml; charset=\"utf-8\"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(),
                            (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpRebind(const std::string& args) {
    std::vector<std::string> tokens;
    std::istringstream iss(args);
    std::string token;
    bool inQuotes = false;
    std::string temp;

    // Split args respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: REBIND [-H \"Header: value\"] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            // Remaining tokens = request body
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"REBIND", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
        if (headers_w.find(L"Content-Type:") == std::wstring::npos)
            headers_w += L"Content-Type: text/xml; charset=\"utf-8\"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(),
                            (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpUnbind(const std::string& args) {
    std::vector<std::string> tokens;
    bool inQuotes = false;
    std::string temp;

    // Split args respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: UNBIND [-H \"Header: value\"] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            // Remaining tokens = request body
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"UNBIND", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
        if (headers_w.find(L"Content-Type:") == std::wstring::npos)
            headers_w += L"Content-Type: text/xml; charset=\"utf-8\"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(),
                            (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpPatchForm(const std::string& args) {
    std::vector<std::string> tokens;
    bool inQuotes = false;
    std::string temp;

    // Split args respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: PATCHFORM [-H \"Header: value\"] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            // Remaining tokens = request body
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"PATCH", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
        if (headers_w.find(L"Content-Type:") == std::wstring::npos)
            headers_w += L"Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(),
                            (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdHttpHug(const std::string& args) {
    std::vector<std::string> tokens;
    bool inQuotes = false;
    std::string temp;

    // Split args respecting quotes
    for (char c : args) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!temp.empty()) { tokens.push_back(temp); temp.clear(); }
        } else {
            temp += c;
        }
    }
    if (!temp.empty()) tokens.push_back(temp);

    if (tokens.empty()) {
        std::cerr << "Usage: HUG [-H \"Header: value\"] <URL> [body]\n";
        return;
    }

    std::vector<std::string> headers;
    std::string url;
    std::string body;

    // Parse arguments
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "-H" && i + 1 < tokens.size()) {
            headers.push_back(tokens[++i]);
        } else if (url.empty()) {
            url = tokens[i];
        } else {
            for (size_t j = i; j < tokens.size(); ++j) {
                if (!body.empty()) body += " ";
                body += tokens[j];
            }
            break;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required.\n";
        return;
    }

    std::wstring wurl = NormalStringgToWideString(url);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        std::cerr << "Failed to parse URL. Error: " << GetLastError() << "\n";
        return;
    }

    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "Failed to open session.\n"; return; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) { std::cerr << "Failed to connect.\n"; WinHttpCloseHandle(hSession); return; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HUG", path, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { std::cerr << "Failed to open request.\n"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers_w;
    for (const auto& h : headers) headers_w += NormalStringgToWideString(h) + L"\r\n";

    std::vector<char> bodyBuffer;
    const void* bodyData = nullptr;
    DWORD bodySize = 0;
    if (!body.empty()) {
        bodyBuffer.assign(body.begin(), body.end());
        bodyData = bodyBuffer.data();
        bodySize = (DWORD)bodyBuffer.size();
        headers_w += L"Content-Length: " + std::to_wstring(bodySize) + L"\r\n";
        if (headers_w.find(L"Content-Type:") == std::wstring::npos)
            headers_w += L"Content-Type: text/xml; charset=\"utf-8\"\r\n";
    }

    if (!headers_w.empty()) headers_w += L"\r\n";

    if (!WinHttpSendRequest(hRequest,
                            headers_w.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers_w.c_str(),
                            (DWORD)headers_w.length(),
                            (void*)bodyData, bodySize, bodySize, 0)) {
        std::cerr << "Failed to send request. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "Failed to receive response. Error: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return;
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &statusCode, &size, nullptr)) {
        std::cout << "HTTP Status Code: " << statusCode << "\n";
    }

    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
        buffer[downloaded] = '\0';
        std::cout << buffer.data();
    } while (dwSize > 0);

    std::cout << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void CmdUpnpSearch(const std::string& args) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket.\n";
        WSACleanup();
        return;
    }

    // Set socket timeout for recvfrom
    DWORD timeout = 3000; // milliseconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(1900);
    inet_pton(AF_INET, "239.255.255.250", &dest.sin_addr);

    std::string msearch =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n";

    if (sendto(sock, msearch.c_str(), (int)msearch.size(), 0, (sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
        std::cerr << "Failed to send M-SEARCH.\n";
        closesocket(sock);
        WSACleanup();
        return;
    }

    std::cout << "Sent UPnP discovery request, waiting for responses...\n";

    char buffer[2048];
    sockaddr_in from;
    int fromLen = sizeof(from);
    bool gotResponse = false;

    auto start = std::chrono::steady_clock::now();
    while (true) {
        int ret = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (sockaddr*)&from, &fromLen);
        if (ret == SOCKET_ERROR) break;

        buffer[ret] = '\0';
        char addrStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &from.sin_addr, addrStr, sizeof(addrStr));

        std::cout << "Response from " << addrStr << ":\n";
        std::cout << buffer << "\n-----------------\n";

        gotResponse = true;

        // Stop after 3 seconds
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() > 3) break;
    }

    if (!gotResponse) {
        std::cout << "No response.\n";
    }

    closesocket(sock);
    WSACleanup();
}

void CmdHttpHelp(const std::string& args) {
    (void)args;
    std::cout << ANSI_BOLD_CYAN "======== HTTP Commands Help ========\n" << ANSI_RESET;
    std::cout << "Available commands:\n";
    std::cout << " - http put <url> <headers|body> [cookies]  : Send an HTTP PUT request.\n";
    std::cout << " - http get <URL> [header1|header2|...] [--cookie-jar file] : Send an HTTP GET request.\n";
    std::cout << " - http head [-H \"Header\"] <url>          : Send an HTTP HEAD request.\n";
    std::cout << " - http post <url> <headers|body>           : Send an HTTP POST request.\n";
    std::cout << " - http delete [-H \"Header\"] <url>        : Send an HTTP DELETE request.\n";
    std::cout << " - http options [-H \"Header\"] <url>       : Send an HTTP OPTIONS request.\n";
    std::cout << " - http link [-H \"Header: value\"] <url>   : Send an HTTP LINK request.\n";
    std::cout << " - http unlink [-H \"Header: value\"] <url> : Send an HTTP UNLINK request.\n";
    std::cout << " - http trace [-H \"Header: value\"] <url>  : Send an HTTP TRACE request.\n";
    std::cout << " - http download <url> <output filename>    : Download a file from the given URL.\n";
    std::cout << " - http propfind [-H \"Header: value\"] <url>: Send an HTTP PROPFIND request.\n";
    std::cout << " - http proppatch [-H \"Header: value\"] [--depth 0|1|infinity] -d \"<xml>\" <url>: Send an HTTP PROPPATCH request.\n";
    std::cout << " - http report [-H \"Header: value\"] [-D depth] <url> [body] : Send an HTTP REPORT request.\n";
    std::cout << " - http mkcol [-H \"Header: value\"] <URL> [body] - Send an HTTP MKCOL request.\n";
    std::cout << " - http bind [-H \"Header: value\"] <URL> [body] - Send an HTTP BIND request.\n";
    std::cout << " - http rebind [-H \"Header: value\"] <URL> [body] - Send an HTTP REBIND request.\n";
    std::cout << " - http unbind [-H \"Header: value\"] <URL> [body] - Send an HTTP UNBIND request.\n";
    std::cout << " - http hug [-H \"Header: value\"] <URL> [body] - Send an HTTP HUG request.\n";
    std::cout << " - http connect <proxyHost:port> <targetHost:port> [-H \"Header: value\"] : Establish an HTTP CONNECT tunnel through the proxy.\n";
    std::cout << " - http patch [-H \"Header\"] [-d \"body\"] <url> : Send an HTTP PATCH request.\n";
    std::cout << " - http patchform [-H \"Header\"] [-d \"body\"] <url> : Send an HTTP PATCH request with form data.\n";
    std::cout << " - http purge <URL> [header1|header2|...] [|payload] : Send an HTTP PURGE request.\n";
    std::cout << " - http upnp                   : Send a UPnP discovery request.\n";   
    std::cout << " - http help                               : Show this help message.\n";
    std::cout << ANSI_BOLD_YELLOW "---------------------------------\n" << ANSI_RESET;
}
