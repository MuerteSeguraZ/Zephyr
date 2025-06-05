
#define _WIN32_WINNT 0x0601  

// Includes (headers)
#include <winsock2.h>        
#include <ws2tcpip.h>        
#include <iphlpapi.h>        
#include <icmpapi.h>
#include <windows.h>        
#include <shlobj.h> 
#include <winhttp.h>         
#include <cfgmgr32.h>
#include <Lmcons.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <lm.h>

// Includes (normal packages)
#include <iostream>
#include <algorithm>
#include <string>
#include <sstream>
#include <unordered_map>
#include <functional>
#include <filesystem>
#include <thread>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <chrono>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <array>
#include <regex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "Netapi32.lib")

// Colors
#define ANSI_BLACK         "\x1b[30m"
#define ANSI_RED           "\x1b[31m"
#define ANSI_GREEN         "\x1b[32m"
#define ANSI_YELLOW        "\x1b[33m"
#define ANSI_BLUE          "\x1b[34m"
#define ANSI_MAGENTA       "\x1b[35m"
#define ANSI_CYAN          "\x1b[36m"
#define ANSI_WHITE         "\x1b[37m"

// Bold Colors
#define ANSI_BOLD_BLACK    "\x1b[1;30m"
#define ANSI_BOLD_RED      "\x1b[1;31m"
#define ANSI_BOLD_GREEN    "\x1b[1;32m"
#define ANSI_BOLD_YELLOW   "\x1b[1;33m"
#define ANSI_BOLD_BLUE     "\x1b[1;34m"
#define ANSI_BOLD_MAGENTA  "\x1b[1;35m"
#define ANSI_BOLD_CYAN     "\x1b[1;36m"
#define ANSI_BOLD_WHITE    "\x1b[1;37m"

// Underlined Colors
#define ANSI_UNDERLINE_BLACK   "\x1b[4;30m"
#define ANSI_UNDERLINE_RED     "\x1b[4;31m"
#define ANSI_UNDERLINE_GREEN   "\x1b[4;32m"
#define ANSI_UNDERLINE_YELLOW  "\x1b[4;33m"
#define ANSI_UNDERLINE_BLUE    "\x1b[4;34m"
#define ANSI_UNDERLINE_MAGENTA "\x1b[4;35m"
#define ANSI_UNDERLINE_CYAN    "\x1b[4;36m"
#define ANSI_UNDERLINE_WHITE   "\x1b[4;37m"

// Background Colors
#define ANSI_BG_BLACK     "\x1b[40m"
#define ANSI_BG_RED       "\x1b[41m"
#define ANSI_BG_GREEN     "\x1b[42m"
#define ANSI_BG_YELLOW    "\x1b[43m"
#define ANSI_BG_BLUE      "\x1b[44m"
#define ANSI_BG_MAGENTA   "\x1b[45m"
#define ANSI_BG_CYAN      "\x1b[46m"
#define ANSI_BG_WHITE     "\x1b[47m"

// High Intensity Foreground
#define ANSI_INTENSE_BLACK     "\x1b[90m"
#define ANSI_INTENSE_RED       "\x1b[91m"
#define ANSI_INTENSE_GREEN     "\x1b[92m"
#define ANSI_INTENSE_YELLOW    "\x1b[93m"
#define ANSI_INTENSE_BLUE      "\x1b[94m"
#define ANSI_INTENSE_MAGENTA   "\x1b[95m"
#define ANSI_INTENSE_CYAN      "\x1b[96m"
#define ANSI_INTENSE_WHITE     "\x1b[97m"

// High Intensity Background
#define ANSI_BG_INTENSE_BLACK     "\x1b[100m"
#define ANSI_BG_INTENSE_RED       "\x1b[101m"
#define ANSI_BG_INTENSE_GREEN     "\x1b[102m"
#define ANSI_BG_INTENSE_YELLOW    "\x1b[103m"
#define ANSI_BG_INTENSE_BLUE      "\x1b[104m"
#define ANSI_BG_INTENSE_MAGENTA   "\x1b[105m"
#define ANSI_BG_INTENSE_CYAN      "\x1b[106m"
#define ANSI_BG_INTENSE_WHITE     "\x1b[107m"

// Special Styles
#define ANSI_RESET         "\x1b[0m"
#define ANSI_BOLD          "\x1b[1m"
#define ANSI_DIM           "\x1b[2m"
#define ANSI_UNDERLINE     "\x1b[4m"
#define ANSI_REVERSE       "\x1b[7m"
#define ANSI_HIDDEN        "\x1b[8m"
#define ANSI_STRIKETHROUGH "\x1b[9m"


namespace fs = std::filesystem;


std::string GetUsername() {
    char username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (GetUserNameA(username, &size)) return std::string(username);
    return "user";
}

std::string GetHostname() {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(hostname, &size)) return std::string(hostname);
    return "host";
}

std::string GetCurrentDir() {
    try {
        return std::filesystem::current_path().string();
    } catch (...) {
        return ".";
    }
}

void PrintPrompt() {
    std::cout << "\033[1;32m" << GetUsername()
              << "\033[0m@\033[1;34m" << GetHostname()
              << "\033[0m:\033[1;33m" << GetCurrentDir()
              << "\033[0m$ ";
}

void CmdList(const std::string& args);
void CmdTreeList(const std::string& args);
void CmdHop(const std::string& args);
void CmdSend(const std::string& args);
void CmdZap(const std::string& args);
void CmdShift(const std::string& args);
void CmdMkplace(const std::string& args);
void CmdClear(const std::string& args);
void CmdBye(const std::string& args);
void CmdLook(const std::string& args);
void CmdRead(const std::string& args);
void CmdPeek(const std::string& args);
void CmdWrite(const std::string& args);
void CmdRun(const std::string& args);
void CmdEchoe(const std::string& args);
void CmdWhereami(const std::string& args);
void CmdSysinfo(const std::string& args);
void CmdLinkup(const std::string& args);
void CmdTouch(const std::string& args);
void CmdFind(const std::string& args);
void CmdDate(const std::string& args);
void CmdEnv(const std::string& args);
void CmdRefreshEnv(const std::string& args);
void CmdHelp(const std::string& args);
void CmdRename(const std::string& args);  
void CmdRadar(const std::string& args);
void CmdEndproc(const std::string& args);
void CmdDiskInfo(const std::string& args);
void CmdDU(const std::string& args);
void CmdSetTitle(const std::string& args);
void ExecuteCommand(const std::string& input);
void CmdSconfig(const std::string& args);
void CmdMConfig(const std::string& args);
void CmdVersion(const std::string& args);
void CmdCuteMessage(const std::string& args);
void CmdSmLink(const std::string& args);
void CmdProcMon(const std::string& args);
void CmdCpuInfo(const std::string& args);
void CmdUptime(const std::string& args);
void CmdNetstat(const std::string& args);
void CmdTempClean(const std::string& args);
void CmdMirror(const std::string& args);
void CmdKillTree(const std::string& args);
void CmdPingTest(const std::string& args);
void CmdHttpGet(const std::string& url);
void CmdHttpPost(const std::string& args);
void CmdHttpHead(const std::string& args);
void CmdScanWrapper(const std::string& args);
void CmdCheckAdminWrapper(const std::string& args);
void CmdListUsersWrapper(const std::string& args);
void CmdStat(const std::string& args);
void CmdDnsFlush(const std::string& args);
void CmdFirewallStatus(const std::string& args);
void CmdDrives(const std::string& args);
void CmdSmartStatus(const std::string& args);
void DeleteContents(const fs::path& dir);

std::unordered_map<std::string, std::function<void(const std::string&)>> commands = {
    {"list", CmdList}, {"tree", CmdTreeList}, {"send", CmdSend}, {"zap", CmdZap}, {"shift", CmdShift},
    {"mkplace", CmdMkplace}, {"clear", CmdClear}, {"bye", CmdBye},
    {"look", CmdLook}, {"read", CmdRead}, {"peek", CmdPeek}, {"write", CmdWrite},
    {"run", CmdRun}, {"echoe", CmdEchoe}, {"whereami", CmdWhereami},
    {"sysinfo", CmdSysinfo}, {"touch", CmdTouch}, {"find", CmdFind},
    {"date", CmdDate}, {"env", CmdEnv}, {"refreshenv", CmdRefreshEnv},
    {"help", CmdHelp}, {"?", CmdHelp},
    {"rename", CmdRename}, {"radar", CmdRadar}, {"endproc", CmdEndproc}, 
    {"linkup", CmdLinkup}, {"diskinfo", CmdDiskInfo}, {"du", CmdDU},
    {"ctitle", CmdSetTitle}, {"sconfig", CmdSconfig}, 
    {"mconfig", CmdMConfig}, {"version", CmdVersion}, {"cutemessage", CmdCuteMessage},
    {"smlink", CmdSmLink}, {"procmon", CmdProcMon}, 
    {"cpuinfo", CmdCpuInfo}, {"uptime", CmdUptime}, {"netstat", CmdNetstat}, {"mirror", CmdMirror}, 
    {"tempclean", CmdTempClean}, {"killtree", CmdKillTree}, {"pingtest", CmdPingTest}, 
    {"get", CmdHttpGet}, {"post", CmdHttpPost}, {"head", CmdHttpHead}, {"scan", CmdScanWrapper}, {"hop", CmdHop}, {"stat", CmdStat},
    {"checkadmin", CmdCheckAdminWrapper}, {"listusers", CmdListUsersWrapper}, {"dnsflush", CmdDnsFlush},
    {"firewall", CmdFirewallStatus}, {"drives", CmdDrives}, {"smart", CmdSmartStatus}
};



int main() {
    
    SetConsoleOutputCP(CP_UTF8);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    while (true) {
        PrintPrompt();
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        std::string args;
        std::getline(iss, args);
        if (!args.empty() && args[0] == ' ') args.erase(0, 1);

        auto it = commands.find(cmd);
        if (it != commands.end()) it->second(args);
        else std::cout << "Command " << cmd << " isn't recognized as an internal or external command." << std::endl;
    }

    WSACleanup();  
    return 0;
}

void CmdPortScan(const std::string& ip, int startPort, int endPort) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    std::cout << "Scanning " << ip << " from port " << startPort << " to " << endPort << "...\n";

    for (int port = startPort; port <= endPort; ++port) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);

        connect(s, (sockaddr*)&addr, sizeof(addr));
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(s, &writeSet);

        timeval timeout = { 0, 200000 }; 
        if (select(0, nullptr, &writeSet, nullptr, &timeout) > 0 && FD_ISSET(s, &writeSet)) {
            std::cout << "Port " << port << " is OPEN\n";
        }

        closesocket(s);
    }

    WSACleanup();
}

void CmdScanWrapper(const std::string& args) {
    std::istringstream iss(args);
    std::string ip;
    int startPort, endPort;

    if (!(iss >> ip >> startPort >> endPort)) {
        std::cout << "Usage: scan <ip> <startPort> <endPort>\n";
        return;
    }

    CmdPortScan(ip, startPort, endPort);
}

void CmdListUsersWrapper(const std::string& args) {
    LPUSER_INFO_0 pBuf = nullptr;
    DWORD dwLevel = 0, dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0;

    NET_API_STATUS nStatus = NetUserEnum(nullptr, dwLevel, FILTER_NORMAL_ACCOUNT,
                                         (LPBYTE*)&pBuf, dwPrefMaxLen,
                                         &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

    if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != nullptr) {
        for (DWORD i = 0; i < dwEntriesRead; ++i) {
            std::wcout << L"User: " << pBuf[i].usri0_name << L"\n";
        }
    } else {
        std::cout << "Failed to list users.\n";
    }

    if (pBuf != nullptr) NetApiBufferFree(pBuf);
}

void CmdStat(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    if (!(iss >> filename)) {
        std::cout << "Usage: stat <filename>\n";
        return;
    }

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExA(filename.c_str(), GetFileExInfoStandard, &fileInfo)) {
        std::cout << "Error: Cannot access file \"" << filename << "\"\n";
        return;
    }

    ULARGE_INTEGER filesize;
    filesize.HighPart = fileInfo.nFileSizeHigh;
    filesize.LowPart = fileInfo.nFileSizeLow;

    SYSTEMTIME stUTC, stLocal;

    auto printFileTime = [](const FILETIME& ft) {
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&ft, &stUTC);
        SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal);
        std::cout << std::setfill('0')
                  << std::setw(2) << stLocal.wDay << "/"
                  << std::setw(2) << stLocal.wMonth << "/"
                  << stLocal.wYear << " "
                  << std::setw(2) << stLocal.wHour << ":"
                  << std::setw(2) << stLocal.wMinute << ":"
                  << std::setw(2) << stLocal.wSecond;
    };

    std::cout << "File: " << filename << "\n";
    std::cout << "Size: " << filesize.QuadPart << " bytes\n";

    std::cout << "Created: ";
    printFileTime(fileInfo.ftCreationTime);
    std::cout << "\n";

    std::cout << "Last Modified: ";
    printFileTime(fileInfo.ftLastWriteTime);
    std::cout << "\n";

    std::cout << "Last Accessed: ";
    printFileTime(fileInfo.ftLastAccessTime);
    std::cout << "\n";

    std::cout << "Attributes: ";
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_READONLY) std::cout << "ReadOnly ";
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) std::cout << "Hidden ";
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) std::cout << "System ";
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) std::cout << "Archive ";
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_NORMAL) std::cout << "Normal ";
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY) std::cout << "Temporary ";
    std::cout << "\n";
}

void CmdNetstat(const std::string& args) {
    std::cout << "Proto\tLocal Address\t\tForeign Address\t\tState" << std::endl;

    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    DWORD tcpSize = 0;
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(tcpSize);

    if (GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
            auto row = tcpTable->table[i];

            in_addr localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            in_addr remoteAddr;
            remoteAddr.S_un.S_addr = row.dwRemoteAddr;

            USHORT localPort = ntohs((u_short)row.dwLocalPort);
            USHORT remotePort = ntohs((u_short)row.dwRemotePort);

            std::string state;
            switch (row.dwState) {
                case MIB_TCP_STATE_ESTAB: state = "ESTABLISHED"; break;
                case MIB_TCP_STATE_LISTEN: state = "LISTENING"; break;
                case MIB_TCP_STATE_SYN_SENT: state = "SYN_SENT"; break;
                case MIB_TCP_STATE_SYN_RCVD: state = "SYN_RCVD"; break;
                case MIB_TCP_STATE_FIN_WAIT1: state = "FIN_WAIT1"; break;
                case MIB_TCP_STATE_FIN_WAIT2: state = "FIN_WAIT2"; break;
                case MIB_TCP_STATE_TIME_WAIT: state = "TIME_WAIT"; break;
                case MIB_TCP_STATE_CLOSING: state = "CLOSING"; break;
                case MIB_TCP_STATE_CLOSE_WAIT: state = "CLOSE_WAIT"; break;
                case MIB_TCP_STATE_LAST_ACK: state = "LAST_ACK"; break;
                case MIB_TCP_STATE_DELETE_TCB: state = "DELETE_TCB"; break;
                default: state = "UNKNOWN"; break;
            }

            std::cout << "TCP\t" 
                      << inet_ntoa(localAddr) << ":" << localPort << "\t\t"
                      << inet_ntoa(remoteAddr) << ":" << remotePort << "\t\t"
                      << state << std::endl;
        }
    }
    free(tcpTable);

    PMIB_UDPTABLE_OWNER_PID udpTable = nullptr;
    DWORD udpSize = 0;
    GetExtendedUdpTable(nullptr, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(udpSize);

    if (GetExtendedUdpTable(udpTable, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; ++i) {
            auto row = udpTable->table[i];
            in_addr localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;

            USHORT localPort = ntohs((u_short)row.dwLocalPort);

            std::cout << "UDP\t" 
                      << inet_ntoa(localAddr) << ":" << localPort << "\t\t"
                      << "*:*" << "\t\t\t"
                      << "-" << std::endl;
        }
    }
    free(udpTable);
}

void CmdHttpGet(const std::string& url) {
    HINTERNET hSession = WinHttpOpen(L"Zephyr/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cout << "Failed to open WinHTTP session\n";
        return;
    }

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    wchar_t host[256], path[1024];
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = 1024;

    std::wstring wurl(url.begin(), url.end());
    WinHttpCrackUrl(wurl.c_str(), wurl.length(), 0, &urlComp);

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0)
        && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            std::vector<char> buffer(dwSize + 1);
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) break;
            buffer[dwDownloaded] = '\0';
            std::cout << buffer.data();
        } while (dwSize > 0);
    } else {
        std::cout << "HTTP GET failed.\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

std::wstring ToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
    if (size_needed <= 0) return std::wstring();
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
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

void CmdHttpHead(const std::string& args) {
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

void DeleteContents(const fs::path& dir) {
    if (!fs::exists(dir)) return;

    for (const auto& entry : fs::directory_iterator(dir)) {
        try {
            fs::remove_all(entry);
        } catch (const std::exception& e) {
            std::cerr << "[TEMPCLEAN] Failed to delete " << entry.path() << ": " << e.what() << "\n";
        }
    }
}

void CmdPingTest(const std::string& args) {
    std::istringstream iss(args);
    std::vector<std::string> tokens;
    std::string token;

    while (iss >> token)
        tokens.push_back(token);

    if (tokens.empty()) {
        std::cout << "[PINGTEST] Usage: pingtest <host> [-t] [-n count] [-l size]\n";
        return;
    }

    std::string host = tokens[0];
    bool continuous = false;
    int count = 4; 
    int size = 32;

    for (size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i] == "-t") {
            continuous = true;
        } else if (tokens[i] == "-n" && i + 1 < tokens.size()) {
            count = std::stoi(tokens[++i]);
        } else if (tokens[i] == "-l" && i + 1 < tokens.size()) {
            size = std::stoi(tokens[++i]);
        }
    }

    sockaddr_in dest = {};
    dest.sin_family = AF_INET;

    if (inet_pton(AF_INET, host.c_str(), &dest.sin_addr) != 1) {
        addrinfo hints = {};
        hints.ai_family = AF_INET;
        addrinfo* res = nullptr;

        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
            std::cerr << "[PINGTEST] Could not resolve host: " << host << "\n";
            return;
        }

        dest.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        std::cerr << "[PINGTEST] IcmpCreateFile failed.\n";
        return;
    }

    std::vector<char> sendData(size, 'x');
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + size;
    std::vector<char> replyBuffer(replySize);

    int sent = 0;
    int received = 0;

    do {
        std::cout << "[PINGTEST] Sending packet to " << host << " ("
                  << inet_ntoa(dest.sin_addr) << ")...\n";

        DWORD result = IcmpSendEcho(
            hIcmp,
            dest.sin_addr.S_un.S_addr,
            sendData.data(),
            (WORD)sendData.size(),
            nullptr,
            replyBuffer.data(),
            replySize,
            1000
        );

        sent++;

        if (result != 0) {
            received++;
            PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer.data();
            std::cout << "[PINGTEST] Reply from "
                      << inet_ntoa(*(in_addr*)&echoReply->Address)
                      << ": bytes=" << echoReply->DataSize
                      << " time=" << echoReply->RoundTripTime << "ms"
                      << " TTL=" << (int)echoReply->Options.Ttl << "\n";
        } else {
            std::cerr << "[PINGTEST] Request timed out.\n";
        }

        if (!continuous) Sleep(1000);
    } while (continuous || sent < count);

    IcmpCloseHandle(hIcmp);

    int lost = sent - received;

    std::cout << "\n--- Ping statistics ---\n";
    std::cout << ANSI_BOLD_GREEN << "Sent:     " << sent << ANSI_RESET << "\n";
    std::cout << ANSI_BOLD_YELLOW << "Received: " << received << ANSI_RESET << "\n";
    std::cout << ANSI_BOLD_RED << "Lost:     " << lost << ANSI_RESET << "\n";
}


bool KillProcessTree(DWORD parentPID) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[KILLTREE] Failed to create snapshot.\n";
        return false;
    }

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    std::vector<DWORD> toKill = { parentPID };

    if (Process32First(snapshot, &pe)) {
        do {
            for (DWORD pid : toKill) {
                if (pe.th32ParentProcessID == pid) {
                    if (std::find(toKill.begin(), toKill.end(), pe.th32ProcessID) == toKill.end()) {
                        toKill.push_back(pe.th32ProcessID);
                    }
                }
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);

    std::reverse(toKill.begin(), toKill.end());
    bool allKilled = true;

    for (DWORD pid : toKill) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            if (TerminateProcess(hProc, 1)) {
                std::cout << "[KILLTREE] Terminated PID: " << pid << "\n";
            } else {
                std::cerr << "[KILLTREE] Failed to terminate PID " << pid
                          << " (Error: " << GetLastError() << ")\n";
                allKilled = false;
            }
            CloseHandle(hProc);
        } else {
            DWORD err = GetLastError();
            std::cerr << "[KILLTREE] Cannot open PID " << pid
                      << " (Error: " << err
                      << (err == 5 ? " - Access Denied" : "") << ")\n";
            allKilled = false;
        }
    }

    return allKilled;
}



void CmdKillTree(const std::string& args) {
    if (args.empty()) {
        std::cout << "[KILLTREE] Usage: killtree <PID>\n";
        return;
    }

    DWORD pid = 0;
    try {
        pid = std::stoul(args);
    } catch (...) {
        std::cerr << "[KILLTREE] Invalid PID provided.\n";
        return;
    }

    if (pid == 0) {
        std::cerr << "[KILLTREE] Cannot kill PID 0.\n";
        return;
    }

    std::cout << "[KILLTREE] Attempting to kill process tree rooted at PID " << pid << "...\n";

    if (KillProcessTree(pid)) {
        std::cout << "[KILLTREE] Process tree terminated successfully.\n";
    } else {
        std::cerr << "[KILLTREE] Some processes could not be terminated.\n";
    }
}



void CmdTempClean(const std::string&) {
    std::vector<std::string> tempPaths;

    char tempBuf[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempBuf)) {
        tempPaths.emplace_back(tempBuf);
    }

    tempPaths.push_back("C:\\Windows\\Temp");
    tempPaths.push_back(std::string(getenv("LOCALAPPDATA")) + "\\Temp");
    tempPaths.push_back("C:\\Windows\\Prefetch");

    std::cout << "[TEMPCLEAN] Cleaning temporary files...\n";

    for (const auto& path : tempPaths) {
        fs::path tempDir = fs::path(path);
        std::cout << "[TEMPCLEAN] Cleaning: " << tempDir << "\n";
        DeleteContents(tempDir);
    }

    std::cout << "[TEMPCLEAN] Temp cleaning complete.\n";
}

void CmdList(const std::string& args) {
    std::string target = args.empty() ? "." : args;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(target)) {
            std::cout << entry.path().filename().string();
            if (entry.is_directory()) std::cout << "\\";
            std::cout << std::endl;
        }
    } catch (const std::exception& ex) {
        std::cout << "Error listing directory: " << ex.what() << std::endl;
    }
}

void CmdTreeList(const std::string& path) {

    try {
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            std::cout << entry.path().string() << "\n";
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

void CmdFirewallStatus(const std::string&) {
    system("netsh advfirewall show allprofiles state");
}


const GUID GUID_DEVCLASS_NET = {0x4d36e972, 0xe325, 0x11ce, {0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};

std::wstring GetDeviceInstanceIdByName(const std::wstring& deviceName) {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return L"";

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        wchar_t buffer[256] = {};
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, nullptr,
                                             (PBYTE)buffer, sizeof(buffer), nullptr)) {
            std::wstring friendlyName(buffer);
            if (friendlyName.find(deviceName) != std::wstring::npos) {
                wchar_t deviceId[512] = {};
                if (SetupDiGetDeviceInstanceIdW(hDevInfo, &devInfoData, deviceId, sizeof(deviceId)/sizeof(wchar_t), nullptr)) {
                    SetupDiDestroyDeviceInfoList(hDevInfo);
                    return std::wstring(deviceId);
                }
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return L"";
}

bool SetDeviceEnabled(const std::wstring& deviceInstanceId, bool enable) {
    DEVINST devInst;
    CONFIGRET cr = CM_Locate_DevNodeW(&devInst, const_cast<wchar_t*>(deviceInstanceId.c_str()), CM_LOCATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS) return false;

    if (enable)
        cr = CM_Enable_DevNode(devInst, 0);
    else
        cr = CM_Disable_DevNode(devInst, 0);

    return cr == CR_SUCCESS;
}

void CmdMConfig(const std::string& args) {
    std::istringstream iss(args);
    std::string token;
    std::vector<std::string> parts;

    bool inQuotes = false;
    std::string current;
    while (iss >> std::quoted(token)) {
        parts.push_back(token);
    }

    if (parts.size() < 2) {
        std::cout << "Usage: mconfig \"Device Name\" enable|disable" << std::endl;
        return;
    }

    std::string deviceName = parts[0];
    std::string action = parts[1];

    std::wstring wDeviceName(deviceName.begin(), deviceName.end());
    bool enable = (action == "enable");

    std::wstring instanceId = GetDeviceInstanceIdByName(wDeviceName);
    if (instanceId.empty()) {
        std::wcout << L"Device '" << wDeviceName << L"' not found." << std::endl;
        return;
    }

    bool success = SetDeviceEnabled(instanceId, enable);
    if (success) {
        std::wcout << (enable ? L"Enabled " : L"Disabled ") << wDeviceName << std::endl;
    } else {
        std::wcout << L"Failed to change state of " << wDeviceName << std::endl;
    }
}

std::wstring CharToWString(const char* str) {
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
    wstr.pop_back(); 
    return wstr;
}

struct ProcInfo {
    DWORD pid;
    std::wstring name;
    SIZE_T memMB;
};

void CmdProcMon(const std::string&) {
    std::vector<ProcInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[procmon] Failed to create process snapshot.\n";
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe)) {
        std::cerr << "[procmon] Failed to retrieve first process.\n";
        CloseHandle(snapshot);
        return;
    }

    do {
        DWORD pid = pe.th32ProcessID;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        SIZE_T memUsage = 0;
        if (hProc) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                memUsage = pmc.WorkingSetSize / (1024 * 1024); 
            }
            CloseHandle(hProc);
        }

        ProcInfo info;
        info.pid = pid;
        info.name = CharToWString(pe.szExeFile);  
        info.memMB = memUsage;
        processes.push_back(info);



    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);

    std::sort(processes.begin(), processes.end(), [](const ProcInfo& a, const ProcInfo& b) {
        return a.memMB > b.memMB;
    });

    std::wcout << L"[procmon] Running Processes:\n";
    std::wcout << std::left << std::setw(6) << L"PID"
               << std::setw(30) << L"Name"
               << std::right << std::setw(12) << L"Memory (MB)\n";
    std::wcout << std::wstring(50, L'-') << L"\n";

    int index = 0;
    for (const auto& p : processes) {
        bool isTop = index < 5;
        if (isTop) std::wcout << ANSI_RED;
        std::wcout << std::left << std::setw(6) << p.pid
                   << std::setw(30) << p.name
                   << std::right << std::setw(12) << p.memMB << L"\n";
        if (isTop) std::wcout << ANSI_RESET;
        ++index;
    }
}

void CmdCpuInfo(const std::string& args) {
    if (!args.empty()) {
        std::cout << "Usage: cpuspeed" << std::endl;
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    unsigned int logicalCount = std::thread::hardware_concurrency();

    DWORD returnLength = 0;
    std::vector<char> buffer;
    if (!GetLogicalProcessorInformation(nullptr, &returnLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cout << "Error retrieving processor information. Code: " << GetLastError() << std::endl;
        return;
    }
    buffer.resize(returnLength);
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION procInfo = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION>(buffer.data());

    if (!GetLogicalProcessorInformation(procInfo, &returnLength)) {
        std::cout << "Error retrieving processor information. Code: " << GetLastError() << std::endl;
        return;
    }

    int physicalCoreCount = 0;
    DWORD count = returnLength / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    DWORD L1 = 0, L2 = 0, L3 = 0;

    for (DWORD i = 0; i < count; ++i) {
        if (procInfo[i].Relationship == RelationProcessorCore)
            physicalCoreCount++;

        if (procInfo[i].Relationship == RelationCache) {
            auto cache = procInfo[i].Cache;
            switch (cache.Level) {
                case 1: L1 = cache.Size; break;
                case 2: L2 = cache.Size; break;
                case 3: L3 = cache.Size; break;
            }
        }
    }

    HKEY hKey;
    DWORD freq = 0;
    DWORD dataSize = sizeof(freq);
    LONG regResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey);
    if (regResult == ERROR_SUCCESS) {
        regResult = RegQueryValueExA(hKey, "~MHz", nullptr, nullptr, reinterpret_cast<BYTE*>(&freq), &dataSize);
        RegCloseKey(hKey);
    }

    char brand[0x40] = {};
    __cpuid(reinterpret_cast<int*>(brand), 0x80000002);
    __cpuid(reinterpret_cast<int*>(brand + 16), 0x80000003);
    __cpuid(reinterpret_cast<int*>(brand + 32), 0x80000004);

    std::cout << "==================== CPU Information ====================" << std::endl;
    std::cout << "CPU Name: " << brand << std::endl;

    std::cout << "Architecture: ";
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: std::cout << "x64 (AMD or Intel)" << std::endl; break;
        case PROCESSOR_ARCHITECTURE_ARM: std::cout << "ARM" << std::endl; break;
        case PROCESSOR_ARCHITECTURE_IA64: std::cout << "Intel Itanium" << std::endl; break;
        case PROCESSOR_ARCHITECTURE_INTEL: std::cout << "x86" << std::endl; break;
        default: std::cout << "Unknown" << std::endl; break;
    }

    std::cout << "CPU Frequency: " << (freq ? std::to_string(freq) + " MHz" : "Unknown") << std::endl;
    std::cout << "Physical cores: " << physicalCoreCount << std::endl;
    std::cout << "Logical processors: " << logicalCount << std::endl;
    std::cout << "Cache Sizes:" << std::endl;
    std::cout << "  L1 Cache: " << (L1 ? std::to_string(L1 / 1024) + " KB" : "Unknown") << std::endl;
    std::cout << "  L2 Cache: " << (L2 ? std::to_string(L2 / 1024) + " KB" : "Unknown") << std::endl;
    std::cout << "  L3 Cache: " << (L3 ? std::to_string(L3 / 1024) + " KB" : "Unknown") << std::endl;
    std::cout << "=========================================================" << std::endl;
}



void CmdSend(const std::string& args) {
    std::istringstream iss(args);
    std::string src, dst;
    iss >> src >> dst;
    if (src.empty() || dst.empty()) {
        std::cout << "Usage: send <source> <destination>" << std::endl;
        return;
    }
    if (CopyFileA(src.c_str(), dst.c_str(), FALSE) == 0)
        std::cout << "Failed to copy file. Error code: " << GetLastError() << std::endl;
}

void CmdSconfig(const std::string& args) {
    std::istringstream iss(args);
    std::string action, serviceName;
    iss >> action >> serviceName;

    if (action.empty()) {
        std::cout << "Usage:\n"
                  << "  sconfig start <service>\n"
                  << "  sconfig stop <service>\n";
        return;
    }

    if (serviceName.empty()) {
        std::cout << "Missing service name.\n";
        return;
    }

    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        std::cout << "Failed to open service manager. Error: " << GetLastError() << std::endl;
        return;
    }

    SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        std::cout << "Failed to open service: " << serviceName << ". Error: " << GetLastError() << std::endl;
        CloseServiceHandle(scManager);
        return;
    }

    if (action == "start") {
        if (!StartService(service, 0, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING)
                std::cout << "Service is already running.\n";
            else
                std::cout << "Failed to start service. Error: " << err << std::endl;
        } else {
            std::cout << "Service started successfully.\n";
        }
    } else if (action == "stop") {
        SERVICE_STATUS status;
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_NOT_ACTIVE)
                std::cout << "Service is not running.\n";
            else
                std::cout << "Failed to stop service. Error: " << err << std::endl;
        } else {
            std::cout << "Service stopped successfully.\n";
        }
    } else {
        std::cout << "Unknown action: " << action << std::endl;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
}

void CmdCheckAdminWrapper(const std::string& args) {
    BOOL isAdmin = FALSE;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    std::cout << (isAdmin ? "Running as Administrator.\n" : "Not running as Administrator.\n");
}


void CmdZap(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: zap <file>" << std::endl;
        return;
    }
    if (!DeleteFileA(args.c_str()))
        std::cout << "Failed to delete file. Error code: " << GetLastError() << std::endl;
}

void CmdShift(const std::string& args) {
    std::istringstream iss(args);
    std::string src, dst;
    iss >> src >> dst;
    if (src.empty() || dst.empty()) {
        std::cout << "Usage: shift <source> <destination>" << std::endl;
        return;
    }
    if (!MoveFileA(src.c_str(), dst.c_str()))
        std::cout << "Failed to move file. Error code: " << GetLastError() << std::endl;
}

void ExecuteCommand(const std::string& input) {
    std::istringstream iss(input);
    std::string cmd;
    iss >> cmd;
    std::string args;
    std::getline(iss, args);
    if (!args.empty() && args[0] == ' ') args.erase(0, 1);

    auto it = commands.find(cmd);
    if (it != commands.end()) {
        it->second(args);
    } else {
        std::cout << "Unknown command: " << cmd << std::endl;
    }
}

void CmdMkplace(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: mkplace <directory>" << std::endl;
        return;
    }
    if (!CreateDirectoryA(args.c_str(), NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS)
            std::cout << "Directory already exists." << std::endl;
        else
            std::cout << "Failed to create directory. Error code: " << err << std::endl;
    }
}

void CmdHop(const std::string& arg) {
    std::string path = arg;

    if (path.empty()) {
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, cwd);
        printf("Current Directory: %s\n", cwd);
        return;
    }

    if (path == "~userhome") {
        PWSTR homePath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Profile, 0, nullptr, &homePath))) {
            char utf8Home[MAX_PATH];
            wcstombs(utf8Home, homePath, MAX_PATH);
            CoTaskMemFree(homePath);
            if (SetCurrentDirectoryA(utf8Home)) {
                printf("Changed to user home: %s\n", utf8Home);
                return;
            }
        }
        printf("Failed to go to user home directory.\n");
        return;
    }

    if (SetCurrentDirectoryA(path.c_str())) {
        char newPath[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, newPath);
        printf("Changed directory to: %s\n", newPath);
    } else {
        printf("Failed to change directory to: %s\n", path.c_str());
    }
}


void CmdRadar(const std::string& args) {
    std::istringstream iss(args);
    std::string start_folder, target;
    if (!(iss >> start_folder >> target)) {
        std::cout << "Usage: radar <folder_to_search_in> <filename_or_foldername>\n";
        return;
    }

    fs::path start_path(start_folder);

    if (!fs::exists(start_path) || !fs::is_directory(start_path)) {
        std::cout << "Invalid start folder: " << start_folder << "\n";
        return;
    }

    bool found = false;

    try {
        for (auto it = fs::recursive_directory_iterator(start_path, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it) {
            try {
                const auto& path = it->path();

                if (path.filename() == target) {
                    std::cout << "Found: " << path << "\n";
                    found = true;
                    break;
                }
            }
            catch (...) {
                continue;
            }
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error during scanning: " << e.what() << "\n";
        return;
    }

    if (!found) {
        std::cout << "Not found: " << target << " in " << start_folder << "\n";
    }
}

void CmdClear(const std::string&) {
    system("cls");
}

void CmdBye(const std::string&) {
    std::cout << "Goodbye!" << std::endl;
    exit(0);
}

void CmdLook(const std::string&) {
    system("tree");
}

void CmdDrives(const std::string&) {
    DWORD drives = GetLogicalDrives();
    std::cout << "Available Drives:\n";
    for (char i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            std::cout << "  " << (char)('A' + i) << ":\\\n";
        }
    }
}

void CmdSmartStatus(const std::string&) {
    std::cout << "SMART status (WMI):\n";
    system("wmic diskdrive get status,name");
}


void CmdRead(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: read <filename>" << std::endl;
        return;
    }
    std::ifstream file(args);
    if (!file) {
        std::cout << "Could not open file." << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::cout << line << std::endl;
    }
}

void CmdWrite(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    iss >> filename;
    std::string content;
    std::getline(iss, content);
    if (!content.empty() && content[0] == ' ') content.erase(0, 1);
    if (filename.empty() || content.empty()) {
        std::cout << "Usage: write <filename> <text>" << std::endl;
        return;
    }
    std::ofstream file(filename, std::ios::app);
    if (!file) {
        std::cout << "Failed to open file." << std::endl;
        return;
    }
    file << content << std::endl;
}

void CmdRun(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: run <program>" << std::endl;
        return;
    }
    system(args.c_str());
}

void CmdEchoe(const std::string& args) {
    std::cout << args << std::endl;
}

void CmdWhereami(const std::string&) {
    std::cout << GetCurrentDir() << std::endl;
}

void CmdSysinfo(const std::string&) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    OSVERSIONINFOEXA osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    if (!GetVersionExA(reinterpret_cast<OSVERSIONINFOA*>(&osvi))) {
        std::cout << "Failed to get Windows version info." << std::endl;
    }

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memStatus);

    auto bytesToGB = [](DWORDLONG bytes) -> double {
        return bytes / 1024.0 / 1024.0 / 1024.0;
    };

    const char* colorLabel = "\033[1;33m";    
    const char* colorValue = "\033[1;36m";    
    const char* colorReset = "\033[0m";

    std::cout << colorLabel << "CPU cores: " << colorValue << si.dwNumberOfProcessors << colorReset << std::endl;

    std::cout << colorLabel << "Processor type: " << colorValue << si.dwProcessorType << colorReset << std::endl;

    std::cout << colorLabel << "Processor architecture: " << colorValue;
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: std::cout << "x64 (AMD or Intel)"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: std::cout << "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM: std::cout << "ARM"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: std::cout << "ARM64"; break;
        case PROCESSOR_ARCHITECTURE_IA64: std::cout << "Intel Itanium"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << colorReset << std::endl;

    std::cout << colorLabel << "Processor level: " << colorValue << si.wProcessorLevel << colorReset << std::endl;
    std::cout << colorLabel << "Processor revision: " << colorValue 
              << (si.wProcessorRevision >> 8) << "." << (si.wProcessorRevision & 0xFF) << colorReset << std::endl;

    std::cout << colorLabel << "Allocation granularity: " << colorValue << si.dwAllocationGranularity << " bytes" << colorReset << std::endl;
    std::cout << colorLabel << "Page size: " << colorValue << si.dwPageSize << " bytes" << colorReset << std::endl;

    std::cout << colorLabel << "Min app addr: " << colorValue << si.lpMinimumApplicationAddress << colorReset << std::endl;
    std::cout << colorLabel << "Max app addr: " << colorValue << si.lpMaximumApplicationAddress << colorReset << std::endl;

    std::cout << colorLabel << "Active processor mask: " << colorValue 
              << "0x" << std::hex << si.dwActiveProcessorMask << std::dec << colorReset << std::endl;

    std::cout << colorLabel << "Windows version: " << colorValue 
              << static_cast<int>(osvi.dwMajorVersion) << "." << static_cast<int>(osvi.dwMinorVersion) 
              << " (Build " << osvi.dwBuildNumber << ")" << colorReset << std::endl;

    std::cout << colorLabel << "Service Pack: " << colorValue << (osvi.szCSDVersion[0] ? osvi.szCSDVersion : "None") << colorReset << std::endl;

    std::cout << colorLabel << "Suite mask: " << colorValue << osvi.wSuiteMask << colorReset << std::endl;

    std::cout << colorLabel << "Product type: " << colorValue;
    switch (osvi.wProductType) {
        case VER_NT_WORKSTATION: std::cout << "Workstation"; break;
        case VER_NT_DOMAIN_CONTROLLER: std::cout << "Domain Controller"; break;
        case VER_NT_SERVER: std::cout << "Server"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << colorReset << std::endl;

    std::cout << colorLabel << "Total physical memory: " << colorValue 
              << std::fixed << std::setprecision(2) << bytesToGB(memStatus.ullTotalPhys) << " GB" << colorReset << std::endl;

    std::cout << colorLabel << "Available physical memory: " << colorValue 
              << std::fixed << std::setprecision(2) << bytesToGB(memStatus.ullAvailPhys) << " GB" << colorReset << std::endl;

    int memLoad = memStatus.dwMemoryLoad;
    const char* memColor = "\033[1;32m";  

    if (memLoad >= 60) {
        memColor = "\033[1;31m";  
    } else if (memLoad >= 40) {
        memColor = "\033[1;33m";  
    }

    std::cout << colorLabel << "Memory load: " << memColor << memLoad << "%" << colorReset << std::endl;
}

void CmdVersion(const std::string&) {
    printf("Zephyr Version 1.0.2\n");
    printf("Update: Hop (cd) command added!!!\n");
    printf("Built on %s at %s\n", __DATE__, __TIME__);
    printf("Using Windows API: %s\n", _WIN32_WINNT >= 0x0601 ? "Windows 7+" : "Older version");
    printf("Using C++ Standard: %s\n", __cplusplus == 201703L ? "C++17" : "Unknown");
    printf("Compiled with: %s\n", __VERSION__);
    printf("Running on: %s %s\n", GetUsername().c_str(), GetHostname().c_str());
    printf("Current Directory: %s\n", GetCurrentDir().c_str());
    printf("Creator: %s\n", "MuerteSeguraZ");
}

void CmdCuteMessage(const std::string&) {
    printf("This for my gf, Joselyn.\n");
    printf("I'll love you everyday of my existence.\n");
    printf("Even if things get freaky in DMs I'll still flow with that.\n");
    printf("We got together against all odds, and I'm grateful we did that.\n");
    printf("I love you.\n");
}

void CmdSmLink(const std::string& args) {
    std::istringstream iss(args);
    std::string typeFlag, target, linkName;
    iss >> typeFlag >> target >> linkName;

    if (typeFlag != "-s" && typeFlag != "-h") {
        std::cerr << "[smlink] Usage: smlink -s|-h <target> <link>\n";
        return;
    }

    if (target.empty() || linkName.empty()) {
        std::cerr << "[smlink] Missing target or link path.\n";
        return;
    }

    std::wstring wTarget = std::filesystem::path(target).wstring();
    std::wstring wLink = std::filesystem::path(linkName).wstring();

    if (typeFlag == "-s") {
        DWORD attributes = GetFileAttributesW(wTarget.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            std::wcerr << L"[smlink] Target does not exist: " << wTarget << L"\n";
            return;
        }

        DWORD flags = (attributes & FILE_ATTRIBUTE_DIRECTORY)
                          ? SYMBOLIC_LINK_FLAG_DIRECTORY
                          : 0;

        if (CreateSymbolicLinkW(wLink.c_str(), wTarget.c_str(), flags)) {
            std::wcout << L"[smlink] Symbolic link created: " << wLink << L" -> " << wTarget << L"\n";
        } else {
            DWORD err = GetLastError();
            std::wcerr << L"[smlink] Failed to create symbolic link. Error code: " << err << L"\n";
        }
    } else if (typeFlag == "-h") {
        if (CreateHardLinkW(wLink.c_str(), wTarget.c_str(), nullptr)) {
            std::wcout << L"[smlink] Hard link created: " << wLink << L" -> " << wTarget << L"\n";
        } else {
            DWORD err = GetLastError();
            std::wcerr << L"[smlink] Failed to create hard link. Error code: " << err << L"\n";
        }
    }
}

std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed - 1, 0); 
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size_needed, nullptr, nullptr);
    return result;
}

void CmdLinkup(const std::string&) {
    ULONG bufferSize = 0;
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);
    if (result != ERROR_BUFFER_OVERFLOW) {
        std::cerr << "[linkup] Failed to get buffer size for adapters. Error: " << result << std::endl;
        return;
    }

    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* adapterAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapterAddresses, &bufferSize);
    if (result != NO_ERROR) {
        std::cerr << "[linkup] Failed to get adapter info. Error: " << result << std::endl;
        return;
    }

    std::cout << "[linkup] Active Network Interfaces:\n";

    for (IP_ADAPTER_ADDRESSES* adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;

        std::string name = adapter->FriendlyName ? WStringToUTF8(adapter->FriendlyName) : "(unknown)";
        std::string desc = adapter->Description ? WStringToUTF8(adapter->Description) : "(unknown)";
        std::cout << "  ↪ Interface Name: " << name << "\n";
        std::cout << "     Network Name: " << desc << "\n";

        std::cout << "     MAC: ";
        if (adapter->PhysicalAddressLength == 0) {
            std::cout << "(none)\n";
        } else {
            for (UINT i = 0; i < adapter->PhysicalAddressLength; ++i) {
                printf("%02X", adapter->PhysicalAddress[i]);
                if (i != adapter->PhysicalAddressLength - 1) printf("-");
            }
            std::cout << "\n";
        }

        bool hasIP = false;
        for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
            if (!ua->Address.lpSockaddr) continue;

            char ipStr[INET6_ADDRSTRLEN] = {0};
            void* addrPtr = nullptr;

            if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                addrPtr = &(ipv4->sin_addr);
            } else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                addrPtr = &(ipv6->sin6_addr);
            }

            if (addrPtr && inet_ntop(ua->Address.lpSockaddr->sa_family, addrPtr, ipStr, sizeof(ipStr))) {
                std::cout << "     IP: " << ipStr << "\n";
                hasIP = true;

                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    uint8_t prefix = ua->OnLinkPrefixLength;
                    if (prefix <= 32) {
                        uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
                        in_addr maskAddr;
                        maskAddr.s_addr = htonl(mask);
                        char maskStr[INET_ADDRSTRLEN] = {};
                        inet_ntop(AF_INET, &maskAddr, maskStr, sizeof(maskStr));
                        std::cout << "     Subnet Mask: " << maskStr << "\n";
                    }
                } else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    std::cout << "     Subnet Prefix Length: /" << static_cast<int>(ua->OnLinkPrefixLength) << "\n";
                }
            }
        }

        if (!hasIP)
            std::cout << "     IP: (none assigned)\n";

        std::cout << "\n";
    }
}

void CmdDiskInfo(const std::string& args) {
    std::string driveLetter = "C:";
    if (!args.empty()) {
        driveLetter = args.substr(0, 2); 
        if (driveLetter.size() < 2 || driveLetter[1] != ':') {
            std::cout << "[diskinfo] Invalid drive letter format. Use like: diskinfo D:\n";
            return;
        }
    }


    char volumeName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0, maxComponentLen = 0, fileSystemFlags = 0;
    char fileSystemName[MAX_PATH + 1] = { 0 };  

    BOOL success = GetVolumeInformationA(
        (driveLetter + "\\").c_str(),
        volumeName,
        sizeof(volumeName),
        &serialNumber,
        &maxComponentLen,
        &fileSystemFlags,
        fileSystemName,
        sizeof(fileSystemName)
    );

    if (!success) {
        std::cout << "[diskinfo] Failed to get volume information for " << driveLetter << "\n";
        return;
    }

    std::cout << "[diskinfo] Drive: " << driveLetter << "\n";
    std::cout << "  Volume Label: " << (strlen(volumeName) ? volumeName : "(none)") << "\n";
    std::cout << "  Serial Number: " << std::hex << std::uppercase
              << ((serialNumber >> 16) & 0xFFFF) << "-"
              << (serialNumber & 0xFFFF) << std::dec << "\n";
    std::cout << "  File System: " << fileSystemName << "\n";
}



void CmdTouch(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: touch <filename>" << std::endl;
        return;
    }
    std::string filename = args;

    std::ofstream file(filename, std::ios::app);
    if (!file) {
        std::cout << "Failed to open or create file." << std::endl;
        return;
    }
    file.close();

    auto ftime = std::filesystem::file_time_type::clock::now();
    std::error_code ec;
    std::filesystem::last_write_time(filename, ftime, ec);
    if (ec) {
        std::cout << "Failed to update timestamp: " << ec.message() << std::endl;
    }
}

void CmdFind(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: find <filename>" << std::endl;
        return;
    }
    std::string target = args;
    bool found = false;
    for (const auto& p : std::filesystem::recursive_directory_iterator(std::filesystem::current_path())) {
        if (p.path().filename() == target) {
            std::cout << "Found: " << p.path().string() << std::endl;
            found = true;
        }
    }
    if (!found) std::cout << "File not found." << std::endl;
}

void CmdSetTitle(const std::string& args) {
    if (args.empty()) {
        std::cout << "[CTITLE] Please provide a title string.\n";
        return;
    }

    if (SetConsoleTitleA(args.c_str())) {
        std::cout << "[CTITLE] Title set to: " << args << "\n";
    } else {
        std::cerr << "[CTITLE] Failed to set the window title.\n";
    }
}

void CopyRecursively(const fs::path& src, const fs::path& dst) {
    for (const auto& entry : fs::recursive_directory_iterator(src)) {
        const auto& relativePath = fs::relative(entry.path(), src);
        const auto destPath = dst / relativePath;

        if (fs::is_directory(entry.status())) {
            fs::create_directories(destPath);
        } else if (fs::is_regular_file(entry.status())) {
            fs::create_directories(destPath.parent_path());
            fs::copy_file(entry.path(), destPath, fs::copy_options::overwrite_existing);
        }
    }
}

void RemoveStaleFiles(const fs::path& src, const fs::path& dst) {
    for (const auto& entry : fs::recursive_directory_iterator(dst)) {
        const auto& relativePath = fs::relative(entry.path(), dst);
        const auto srcPath = src / relativePath;

        if (!fs::exists(srcPath)) {
            fs::remove_all(entry.path());
        }
    }
}

void CmdMirror(const std::string& args) {
    std::istringstream iss(args);
    std::string source, destination;
    iss >> source >> destination;

    if (source.empty() || destination.empty()) {
        std::cerr << "[MIRROR] Usage: mirror <source> <destination>\n";
        return;
    }

    try {
        fs::path srcPath = source;
        fs::path dstPath = destination;

        if (!fs::exists(srcPath) || !fs::is_directory(srcPath)) {
            std::cerr << "[MIRROR] Source folder does not exist or is not a directory.\n";
            return;
        }

        CopyRecursively(srcPath, dstPath);
        std::cout << "[MIRROR] Mirror completed successfully from " << source << " to " << destination << ".\n";
    } catch (const std::exception& e) {
        std::cerr << "[MIRROR] Error: " << e.what() << "\n";
    }
}

void CmdUptime(const std::string& args) {
    if (!args.empty()) {
        std::cout << "Usage: uptime" << std::endl;
        return;
    }

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULARGE_INTEGER now;
    now.LowPart = ftNow.dwLowDateTime;
    now.HighPart = ftNow.dwHighDateTime;

    ULONGLONG uptimeMs = GetTickCount64();
    ULONGLONG uptimeIntervals = uptimeMs * 10000; 

    ULARGE_INTEGER bootTime;
    bootTime.QuadPart = now.QuadPart - uptimeIntervals;

    FILETIME ftBoot;
    ftBoot.dwLowDateTime = bootTime.LowPart;
    ftBoot.dwHighDateTime = bootTime.HighPart;

    SYSTEMTIME stBoot;
    FileTimeToSystemTime(&ftBoot, &stBoot);

    std::cout << "System Boot Time: "
              << std::setfill('0') << std::setw(2) << stBoot.wDay << "/"
              << std::setfill('0') << std::setw(2) << stBoot.wMonth << "/"
              << stBoot.wYear << " "
              << std::setfill('0') << std::setw(2) << stBoot.wHour << ":"
              << std::setfill('0') << std::setw(2) << stBoot.wMinute << ":"
              << std::setfill('0') << std::setw(2) << stBoot.wSecond
              << std::endl;

    ULONGLONG seconds = uptimeMs / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    seconds %= 60;
    minutes %= 60;
    hours %= 24;

    std::cout << "System Uptime: ";
    if (days > 0) std::cout << days << "d ";
    if (hours > 0 || days > 0) std::cout << hours << "h ";
    if (minutes > 0 || hours > 0 || days > 0) std::cout << minutes << "m ";
    std::cout << seconds << "s" << std::endl;
}

bool EndProcessByName(const std::string& processName) {
    bool success = false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot.\n";
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            std::string exeName = pe.szExeFile;
            if (_stricmp(exeName.c_str(), processName.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess != NULL) {
                    if (TerminateProcess(hProcess, 1)) {
                        std::cout << "Process " << processName << " (PID " << pe.th32ProcessID << ") terminated.\n";
                        success = true;
                    } else {
                        std::cerr << "Failed to terminate process " << processName << ".\n";
                    }
                    CloseHandle(hProcess);
                } else {
                    std::cerr << "Unable to open process " << processName << ".\n";
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    } else {
        std::cerr << "Failed to get first process.\n";
    }

    CloseHandle(hSnapshot);
    return success;
}

void CmdPeek(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    int lines = 10; 
    iss >> filename >> lines;

    if (filename.empty()) {
        std::cout << "Usage: peek <file> [lines]\n";
        return;
    }

    std::ifstream file(filename);
    if (!file) {
        std::cout << "File not found: " << filename << "\n";
        return;
    }

    std::string line;
    for (int i = 0; i < lines && std::getline(file, line); ++i) {
        std::cout << line << "\n";
    }
}

ULONGLONG GetDirectorySize(const std::wstring& directory) {
    ULONGLONG totalSize = 0;
    WIN32_FIND_DATAW findFileData;
    std::wstring searchPath = directory + L"\\*";

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Error: Cannot open directory " << directory << L"\n";
        return 0;
    }

    do {
        const std::wstring filename = findFileData.cFileName;

        if (filename == L"." || filename == L"..")
            continue;

        std::wstring fullPath = directory + L"\\" + filename;

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            totalSize += GetDirectorySize(fullPath);
        } else {
            ULARGE_INTEGER fileSize;
            fileSize.HighPart = findFileData.nFileSizeHigh;
            fileSize.LowPart = findFileData.nFileSizeLow;
            totalSize += fileSize.QuadPart;
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
    return totalSize;
}

void PrintHumanReadableSize(ULONGLONG size) {
    const char* suffixes[] = { "B", "KB", "MB", "GB", "TB" };
    double readableSize = (double)size;
    int suffixIndex = 0;

    while (readableSize >= 1024 && suffixIndex < 4) {
        readableSize /= 1024;
        ++suffixIndex;
    }

    std::cout << std::fixed << std::setprecision(2) << readableSize << " " << suffixes[suffixIndex] << "\n";
}

void CmdDU(const std::string& args) {
    std::wstring directory;

    if (args.empty()) {
        wchar_t cwd[MAX_PATH];
        if (!GetCurrentDirectoryW(MAX_PATH, cwd)) {
            std::cout << "Error: Cannot get current directory\n";
            return;
        }
        directory = cwd;
    } else {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, args.c_str(), (int)args.size(), NULL, 0);
        std::wstring wargs(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, args.c_str(), (int)args.size(), &wargs[0], size_needed);
        directory = wargs;
    }

    ULONGLONG size = GetDirectorySize(directory);
    std::cout << "Directory: ";
    std::wcout << directory << "\nTotal Size: ";
    PrintHumanReadableSize(size);
}

void CmdEndproc(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: endproc <processname.exe>\n";
        return;
    }
    if (!EndProcessByName(args)) {
        std::cout << "No process named '" << args << "' found or failed to terminate.\n";
    }
}

void CmdDate(const std::string&) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::cout << std::ctime(&now_time);
}

void CmdEnv(const std::string&) {
    extern char** environ;
    for (char** env = environ; *env != nullptr; env++) {
        std::cout << *env << std::endl;
    }
}

void CmdRefreshEnv(const std::string&) {
    std::cout << "Environment variables refreshed." << std::endl;
}

void CmdRename(const std::string& args) {
    std::istringstream iss(args);
    std::string oldName, newName;
    iss >> oldName >> newName;

    if (oldName.empty() || newName.empty()) {
        std::cout << "Usage: rename <oldname> <newname>" << std::endl;
        return;
    }

    try {
        std::filesystem::rename(oldName, newName);
        std::cout << "Renamed \"" << oldName << "\" to \"" << newName << "\"" << std::endl;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cout << "Rename failed: " << e.what() << std::endl;
    }
}

void CmdDnsFlush(const std::string&) {
    system("ipconfig /flushdns");
    std::cout << "DNS cache flushed.\n";
}

void CmdHelp(const std::string&) {
    std::cout <<
    "ZEPHYR COMMAND HELP\n"
    "====================================================================================================\n"
    "| Commands:                                                                                        |\n"
    "| list [dir]          - List directory contents                                                    |\n"
    "| tree                - Show all files in a specified directory (by path)                          |\n"
    "| hop [dir/noargs/~userhome] - Takes you to a specified directory. If not, says current dir info.  |\n"
    "| send <src> <dst>    - Copy file                                                                  |\n"
    "| zap <file>          - Delete file                                                                |\n"
    "| shift <src> <dst>   - Move/rename file                                                           |\n"
    "| mkplace <dir>       - Create directory                                                           |\n"
    "| clear               - Clear screen                                                               |\n"
    "| bye                 - Exit shell                                                                 |\n"
    "| look                - Show directory tree                                                        |\n"
    "| read <file>         - Display file contents                                                      |\n"
    "| peek <file>         - Display first few lines of a specified file.                               |\n"
    "| write <file> <text> - Append text to file                                                        |\n"
    "| run <program>       - Run program                                                                |\n"
    "| echoe <text>        - Echo text                                                                  |\n"
    "| whereami            - Show current directory                                                     |\n"
    "| sysinfo             - Show system info                                                           |\n"
    "| du                  - Show disk usage of directory, extern files work with the path.             |\n"
    "| diskinfo [C:/D:]    - Show disk info (default C:)                                                |\n"
    "| linkup              - Displays network interface information                                     |\n"
    "| touch <file>        - Create or update file timestamp                                            |\n"
    "| find <file>         - Search file recursively                                                    |\n"
    "| date                - Show current date and time                                                 |\n"
    "| env                 - Show environment variables                                                 |\n"
    "| refreshenv          - Refresh environment variables                                              |\n"
    "| help or ?           - Show this help                                                             |\n"
    "| rename <old> <new>  - Rename a file or directory                                                 |\n"
    "| radar <folder_to_search_in> <filename_or_foldername> - Search for a file or folder recursively   |\n"
    "| endproc <processname.exe> - Terminate a process by name                                          |\n"
    "| ctitle <title> - Change the console window title                                                 |\n"
    "| sconfig <start|stop> <service> - Start or stop a Windows service                                 |\n"
    "| mconfig <device_name> <enable|disable> - Enable or disable a device by name                      |\n"
    "| version             - Show shell version and build info                                          |\n"
    "| smlink [-s/-h] <target> <link> - Create a symbolic link                                          |\n"
    "| procmon             - Monitor running processes and their memory usage                           |\n"
    "| cpuinfo             - Show CPU info                                                              |\n"
    "| uptime              - Show system uptime                                                         |\n"
    "| netstat             - Show network connections and listening ports                               |\n"
    "| mirror <source> <destination> - Mirror a directory structure                                     |\n"
    "| killtree <pid>      - Terminate a process tree by PID                                            |\n"
    "| pingtest <host>     - Ping a host and display results continuously                               |\n"
    "| scan <host>         - Scan for open ports on a host                                              |\n"
    "| get <url>           - Performs a GET request to the specified URL and displays the response      |\n"
    "| post [-H \"Header\"] [-T content-type] -d <body> <url> - Sends a POST request and shows response |\n"
    "| head <url> [-H \"Header\"] - Sends HEAD request and shows response headers                       |\n"
    "| stat <filename>     - Prints statistics of a given file                                          |\n"
    "| cutemessage         - This is for my gf guys please don't run it                                 |\n"
    "| checkadmin          - Check if the process is running as admin                                   |\n"
    "| listusers           - Lists all active users in a PC                                             |\n"
    "| dnsflush            - Flush DNS resolver cache                                                   |\n"
    "| firewall            - Show Windows firewall status                                               |\n"
    "| drives              - List all available logical drives                                          |\n"
    "| smart               - Display SMART status of disk drives                                        |\n"
    "====================================================================================================\n";
}


