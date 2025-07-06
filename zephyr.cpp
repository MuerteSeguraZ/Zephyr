// So yeah, I'm a junior developer, and I've been digging into Windows system programming and command-line utilities. This is a shell I made.

#define UNICODE
#define _UNICODE

#define _WIN32_WINNT 0x0601

#ifndef FILE_SUPPORTS_COMPRESSION
#define FILE_SUPPORTS_COMPRESSION 0x00000010
#endif

// Windows headers (order matters)
#include <winsock2.h>        
#include <ws2tcpip.h>        
#include <iphlpapi.h>        
#include <icmpapi.h>
#include <windows.h>  
#include <wuapi.h>
#include <sddl.h>          
#include <lmcons.h>       
#include <userenv.h>       
#include <wincrypt.h>
#include <Wtsapi32.h>
#include <wbemidl.h>
#include <comdef.h>
#include <lm.h>
#undef HLOG 
#include <pdh.h>
#include <pdhmsg.h>
#include <initguid.h>
#include <devguid.h> 
#include <shlobj.h>
#include <knownfolders.h>
#include <winhttp.h>
#include <usbiodef.h>         
#include <cfgmgr32.h>
#include <Lmcons.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <intrin.h>
#include <lm.h>
#include <zlib.h>

// C++ standard library
#include <iostream>
#include <algorithm>
#include <cctype>
#include <codecvt>
#include <string>
#include <sstream>
#include <unordered_map>
#include <functional>
#include <filesystem>
#include <thread>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <vector>
#include <chrono>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <array>
#include <random>
#include <regex>
#include <locale>

// Big commands!
#include "bigcommands/inspect.h"
#include "list/list.h"
#include "http/http.h"
#include "ANSI/ANSI_COLORS_H.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")

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
void CmdFZap(const std::string& args);
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
void CmdBattery(const std::string& args);
void CmdLinkup(const std::string& args);
void CmdNetworkAdapters(const std::string& args);
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
void CmdGPUInfo(const std::string& args);
void CmdBIOSInfo(const std::string& args);
void CmdRamInfo(const std::string& args);
void CmdUserInfo(const std::string& args);
void CmdWhoAmI(const std::string& args);
void CmdUptime(const std::string& args);
void CmdNetstat(const std::string& args);
void CmdTempClean(const std::string& args);
void CmdMirror(const std::string& args);
void CmdKillTree(const std::string& args);
void CmdPingTest(const std::string& args);
void CmdScanWrapper(const std::string& args);
void CmdCheckAdminWrapper(const std::string& args);
void CmdStat(const std::string& args);
void CmdFMeta(const std::string& args);
void CmdFHash(const std::string& args);
void CmdDnsFlush(const std::string& args);
void CmdFirewallStatus(const std::string& args);
void CmdSmartStatus(const std::string& args);
void CmdDrives(const std::string& args);
void CmdLsusb(const std::string& args);
void CmdTar(const std::string& args);
void CmdGzip(const std::string& args);
void CmdGunzip(const std::string& args);
void CmdZip(const std::string& args);
void CmdUnzip(const std::string& args);
void CmdGrep(const std::string& args);
void CmdSed(const std::string& args);
void CmdBasename(const std::string& args);
void CmdHead(const std::string& args);
void CmdTail(const std::string& args);
void CmdWc(const std::string& args);
void CmdLoadAvg(const std::string& args);
void CmdWinLoadAvg(const std::string& args);
void CmdStartupApps(const std::string& args);
void CmdMounts(const std::string& args);
void CmdGroups(const std::string& args);
void CmdHexdump(const std::string& args);
void CmdJobs(const std::string& args);
void CmdBgJob(const std::string& args);
void CmdFgJob(const std::string& args);
void CmdStopJob(const std::string& args);
void CmdStartJob(const std::string& args);
void CmdClipCopy(const std::string& args);
void CmdFSize(const std::string& arg);
void CmdDrywall(const std::string& args);
bool RunBatchIfExists(const std::string& cmd, const std::string& args);
void DeleteContents(const fs::path& dir);
void CmdInspect(const std::string& args) {
    std::istringstream iss(args);
    std::string subcmd;
    iss >> subcmd;

    std::string remainingArgs;
    std::getline(iss, remainingArgs);
    remainingArgs.erase(0, remainingArgs.find_first_not_of(" \t"));

    if (subcmd == "file") {
        CmdInspectFile(remainingArgs);
    } else if (subcmd == "proc") {
        CmdInspectProc(remainingArgs);
    } else if (subcmd == "user") {
        CmdInspectUser(remainingArgs);
    } else if (subcmd == "mem") {
        CmdInspectMem(remainingArgs);
    } else if (subcmd == "net") {
        CmdInspectNet(remainingArgs);
    } else if (subcmd == "win") {
        CmdInspectWin(remainingArgs);
    } else if (subcmd == "env") {
        CmdInspectEnv(remainingArgs);
    } else if (subcmd == "boot") {
        CmdInspectBoot(remainingArgs);
    } else if (subcmd == "help" || subcmd.empty()) {
        CmdInspectHelp(remainingArgs);
    } else {
        std::cerr << "Usage: inspect <file|proc|user|mem|net|win|env|boot> [args]\n";
    }
}

void CmdUserMgmt(const std::string& args) {
    std::istringstream iss(args);
    std::string subcmd;
    iss >> subcmd;

    std::string remainingArgs;
    std::getline(iss, remainingArgs);
    remainingArgs.erase(0, remainingArgs.find_first_not_of(" \t"));

if (subcmd == "listusers") {
    CmdListUsers(remainingArgs);
} else if (subcmd == "listgroups" || subcmd == "listlocalgroups") {
    CmdListGroups(remainingArgs);
} else if (subcmd == "listloggedin") {
    CmdListLoggedIn(remainingArgs);
} else if (subcmd == "listlastlogons") {
    CmdListLastLogons(remainingArgs);
} else if (subcmd == "listadmins") {
    CmdListAdmins(remainingArgs);
} else if (subcmd == "listprofiles") {
    CmdListProfiles(remainingArgs);
} else if (subcmd == "listdomains") {
    CmdListDomains(remainingArgs);
} else if (subcmd == "listprocessusers") {
    CmdListProcessUsers(remainingArgs);
} else if (subcmd == "listprivileges") {
    CmdListPrivileges(remainingArgs);
} else if (subcmd == "listuserdetails") {
    CmdListUserDetails(remainingArgs);
} else if (subcmd == "listnetworkusers") {
    CmdListNetworkUsers(remainingArgs);
} else if (subcmd == "listlocalusers") {
    CmdListLocalUsers(remainingArgs);
} else if (subcmd == "listgroupmembers") {
    CmdListGroupMembers(remainingArgs);
} else if (subcmd == "listremotesessions") {
    CmdListRemoteSessions(remainingArgs);
} else if (subcmd == "listdisabledusers") {
    CmdListDisabledUsers(remainingArgs);
} else if (subcmd == "listdrives") {
    CmdListDrives(remainingArgs);
} else if (subcmd == "listvolumes") {
    CmdListVolumes(remainingArgs);
} else if (subcmd == "help" || subcmd == "?") {
    CmdListHelp(remainingArgs);  
} else if (subcmd == "usermgmthelp" || subcmd.empty()) {
    CmdListHelp("");  
} else {
    CmdListHelp("");
    }
 }

void CmdHttp(const std::string& args) {
    std::istringstream iss(args);
    std::string subcmd;
    iss >> subcmd;

    std::string remainingArgs;
    std::getline(iss, remainingArgs);
    remainingArgs.erase(0, remainingArgs.find_first_not_of(" \t"));

    if (subcmd == "put") {
        CmdHttpPut(remainingArgs);
    } else if (subcmd == "get") {
        CmdHttpGet(remainingArgs);
    } else if (subcmd == "post") {
        CmdHttpPost(remainingArgs);
    } else if (subcmd == "head") {
        CmdHttpHeader(remainingArgs);
    } else if (subcmd == "delete") {
        CmdHttpDelete(remainingArgs);
    } else if (subcmd == "patch") {
        CmdHttpPatch(remainingArgs);
    } else if (subcmd == "options") {
        CmdHttpOptions(remainingArgs);
    } else if (subcmd == "link") {
        CmdHttpLink(remainingArgs);
    } else if (subcmd == "unlink") {
        CmdHttpUnlink(remainingArgs);
    } else if (subcmd == "trace") {
        CmdHttpTrace(remainingArgs);
    } else if (subcmd == "connect") {
        CmdHttpConnect(remainingArgs);
    } else if (subcmd == "propfind") {
        CmdHttpPropFind(remainingArgs);
    } else if (subcmd == "download") {
        CmdHttpDownload(remainingArgs);
    } else if (subcmd == "purge") {
        CmdHttpPurge(remainingArgs);  
    } else if (subcmd == "help" || subcmd == "?") {
        CmdHttpHelp(remainingArgs);
    } else {
        CmdHttpHelp(remainingArgs);
    }
}

std::unordered_map<std::string, std::function<void(const std::string&)>> commands = {
    {"list", CmdList}, {"tree", CmdTreeList}, {"send", CmdSend}, {"zap", CmdZap}, {"fzap", CmdFZap}, {"fhash", CmdFHash}, {"shift", CmdShift},
    {"mkplace", CmdMkplace}, {"clear", CmdClear}, {"bye", CmdBye},
    {"look", CmdLook}, {"read", CmdRead}, {"peek", CmdPeek}, {"write", CmdWrite},
    {"run", CmdRun}, {"echoe", CmdEchoe}, {"whereami", CmdWhereami},
    {"sysinfo", CmdSysinfo}, {"battery", CmdBattery}, {"touch", CmdTouch}, {"find", CmdFind},
    {"date", CmdDate}, {"env", CmdEnv}, {"refreshenv", CmdRefreshEnv},
    {"help", CmdHelp}, {"?", CmdHelp},
    {"rename", CmdRename}, {"radar", CmdRadar}, {"endproc", CmdEndproc}, {"drywallmaster", CmdDrywall}, 
    {"linkup", CmdLinkup}, {"ntwkadp", CmdNetworkAdapters}, {"diskinfo", CmdDiskInfo}, {"du", CmdDU},
    {"ctitle", CmdSetTitle}, {"sconfig", CmdSconfig}, {"startupapps", CmdStartupApps}, 
    {"mconfig", CmdMConfig}, {"version", CmdVersion}, {"cutemessage", CmdCuteMessage},
    {"smlink", CmdSmLink}, {"procmon", CmdProcMon}, 
    {"cpuinfo", CmdCpuInfo}, {"uptime", CmdUptime}, {"netstat", CmdNetstat}, {"mirror", CmdMirror}, 
    {"tempclean", CmdTempClean}, {"killtree", CmdKillTree}, {"pingtest", CmdPingTest}, 
    {"scan", CmdScanWrapper}, {"hop", CmdHop}, {"stat", CmdStat}, {"fmeta", CmdFMeta}, {"fsize", CmdFSize},
    {"checkadmin", CmdCheckAdminWrapper}, {"dnsflush", CmdDnsFlush},
    {"firewall", CmdFirewallStatus}, {"drives", CmdDrives}, {"smart", CmdSmartStatus}, {"lsusb", CmdLsusb},
    {"tar", CmdTar}, {"gzip", CmdGzip}, {"gunzip", CmdGunzip}, {"zip", CmdZip}, {"unzip", CmdUnzip}, 
    {"grep", CmdGrep}, {"sed", CmdSed}, {"basename", CmdBasename}, {"head", CmdHead}, {"tail", CmdTail}, {"wc", CmdWc}, {"loadavg", CmdLoadAvg}, {"winloadavg", CmdWinLoadAvg},
    {"mounts", CmdMounts}, {"gpuinfo", CmdGPUInfo}, {"biosinfo", CmdBIOSInfo}, {"raminfo", CmdRamInfo}, {"userinfo", CmdUserInfo}, {"whoami", CmdWhoAmI}, {"groups", CmdGroups}, {"hexdump", CmdHexdump},
    {"jobs", CmdJobs}, {"bgjob", CmdBgJob}, {"fgjob", CmdFgJob}, {"stopjob", CmdStopJob}, {"startjob", CmdStartJob}, {"clipcopy", CmdClipCopy},
    {"inspect", CmdInspect}, {"usermgmt", CmdUserMgmt}, {"http", CmdHttp}
};

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

// Executables

bool RunExeIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string exeFilename = command + ".exe";

    if (fs::exists(exeFilename)) {
        std::string fullCmd = "\"" + exeFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        int ret = std::system(fullCmd.c_str());
        return (ret == 0);  
    } else {
        return false;
    }
}

// Powershell

bool RunPowershellIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string ps1Filename = command + ".ps1";

    if (fs::exists(ps1Filename)) {
        std::string fullCmd = "powershell.exe -ExecutionPolicy Bypass -File \"" + ps1Filename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;
    } else {
        return false;
    }
}


bool RunVbsIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string vbsFilename = command + ".vbs";

    if (fs::exists(vbsFilename)) {
        std::string fullCmd = "cscript.exe //NoLogo \"" + vbsFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;
    } else {
        return false;
    }
}

bool RunShellIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string shFilename = command + ".sh";

    if (fs::exists(shFilename)) {
        std::string fullCmd = "bash \"" + shFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;
        } else {
            return false;
        }
}

bool RunPythonIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string pyFilename = command + ".py";

    if (fs::exists(pyFilename)) {
        std::string fullCmd = "py \"" + pyFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;
    } else {
        return false;
    }
} 

bool RunJavaScriptIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string jsFilename = command + ".js";

    if (fs::exists(jsFilename)) {
        std::string fullCmd = "node \"" + jsFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;
    } else {
        return false;
    }
}

// C++

bool RunCppIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string cppFilename = command + ".cpp";

    if (fs::exists(cppFilename)) {
        std::string compileCmd = "g++ \"" + cppFilename + "\" -o temp.exe";
        if (std::system(compileCmd.c_str()) != 0) {
            return false;
        }

        std::string runCmd = "temp.exe";
        if (!args.empty()) {
            runCmd += " " + args;
        }
        std::system(runCmd.c_str());

        std::remove("temp.exe");

        return true;
    } else {
        return false;
    }
}

// ZShell (.zsh)

bool RunZshIfExists(const std::string& command, std::string& args) {
    namespace fs = std::filesystem;

    std::string zshFilename = command + ".zsh";

    if (fs::exists(zshFilename)) {
        std::string fullCmd = "zsh \"" + zshFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;
    } else {
        return false;
    }
}

int main() {
    EnableVirtualTerminalProcessing();

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
        if (it != commands.end()) {
            it->second(args);
        } else {
            if (!RunBatchIfExists(cmd, args)) {
                if (!RunExeIfExists(cmd, args)) {
                    if (!RunPowershellIfExists(cmd, args)) {
                        if (!RunVbsIfExists(cmd, args)) {
                            if (!RunShellIfExists(cmd, args)) {
                                if (!RunPythonIfExists(cmd, args)) {
                                    if (!RunJavaScriptIfExists(cmd, args)) {
                                        if (!RunZshIfExists(cmd, args)) {
                                            std::cout << "Command '" << cmd << "' isn't recognized as an internal or external command." << std::endl;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }  
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

std::string AddThousandsCommas(const std::string& numStr) {
    int len = (int)numStr.length();
    int commas = (len - 1) / 3;
    if (commas == 0) return numStr;

    std::string result;
    int firstGroupLen = len - commas * 3;
    result = numStr.substr(0, firstGroupLen);

    for (int i = 0; i < commas; ++i) {
        result += ",";
        result += numStr.substr(firstGroupLen + i * 3, 3);
    }
    return result;
}

void CmdFSize(const std::string& arg) {
    if (arg.empty()) {
        std::cerr << "Usage: fsize <bytes>\n";
        return;
    }

    uint64_t bytes = 0;
    try {
        bytes = std::stoull(arg);
    } catch (...) {
        std::cerr << "Invalid input: " << arg << "\n";
        return;
    }

    const double KB = 1000.0;
    const double MB = KB * 1000.0;
    const double GB = MB * 1000.0;
    const double TB = GB * 1000.0;

    double value = 0.0;
    std::string unit;

    if (bytes >= TB) {
        value = bytes / TB;
        unit = "TB";
    } else if (bytes >= GB) {
        value = bytes / GB;
        unit = "GB";
    } else if (bytes >= MB) {
        value = bytes / MB;
        unit = "MB";
    } else if (bytes >= KB) {
        value = bytes / KB;
        unit = "KB";
    } else {
        value = (double)bytes;
        unit = "bytes";
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << value;
    std::string formatted = oss.str();

    size_t dotPos = formatted.find('.');
    if (dotPos != std::string::npos) {
        formatted[dotPos] = ',';
    }

    std::string intPart = dotPos == std::string::npos ? formatted : formatted.substr(0, dotPos);
    std::string fracPart = dotPos == std::string::npos ? "" : formatted.substr(dotPos);

    intPart = AddThousandsCommas(intPart);

    std::cout << intPart << fracPart << " " << unit << "\n";
}

void CmdHexdump(const std::string& args) {
    std::string filename = args;
    if (filename.empty()) {
        std::cerr << "Usage: hexdump <file>\n";
        return;
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << "\n";
        return;
    }

    unsigned char buffer[16];
    std::streamsize bytesRead;
    size_t offset = 0;

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || (bytesRead = file.gcount())) {
        bytesRead = file.gcount();
        std::cout << std::setw(8) << std::setfill('0') << std::hex << offset << "  ";

        for (int i = 0; i < 16; ++i) {
            if (i < bytesRead)
                std::cout << std::setw(2) << (int)buffer[i] << " ";
            else
                std::cout << "   ";
            if (i == 7) std::cout << " ";
        }

        std::cout << " |";
        for (int i = 0; i < bytesRead; ++i) {
            char c = buffer[i];
            std::cout << (std::isprint(c) ? c : '.');
        }
        std::cout << "|\n";

        offset += bytesRead;
    }
}

void CmdFHash(const std::string& args) {
    std::string filename = args;
    if (filename.empty()) {
        std::cerr << ANSI_RED << "Usage: fhash <file>\n" << ANSI_RESET;
        return;
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << ANSI_RED << "Failed to open file: " << filename << "\n" << ANSI_RESET;
        return;
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << ANSI_RED << "CryptAcquireContext failed.\n" << ANSI_RESET;
        return;
    }

    struct HashAlg {
        ALG_ID algId;
        std::string name;
    };

    std::vector<HashAlg> algs = {
        { CALG_MD5,       "MD5" },
        { CALG_SHA1,      "SHA1" },
        { CALG_SHA_256,   "SHA256" },
        { CALG_SHA_384,   "SHA384" },
        { CALG_SHA_512,   "SHA512" }
    };

    for (const auto& alg : algs) {
        HCRYPTHASH hHash = 0;
        if (!CryptCreateHash(hProv, alg.algId, 0, 0, &hHash)) {
            std::cerr << ANSI_RED << "CryptCreateHash failed for " << alg.name << "\n" << ANSI_RESET;
            continue;
        }

        std::ifstream f(filename, std::ios::binary);
        std::vector<char> buffer(8192);
        while (f.read(buffer.data(), buffer.size()) || f.gcount()) {
            if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer.data()), static_cast<DWORD>(f.gcount()), 0)) {
                std::cerr << ANSI_RED << "CryptHashData failed for " << alg.name << "\n" << ANSI_RESET;
                CryptDestroyHash(hHash);
                break;
            }
        }

        BYTE hash[64];
        DWORD hashLen = sizeof(hash);
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            std::cout << ANSI_CYAN << std::setw(7) << std::left << alg.name << ANSI_RESET << ": " << ANSI_GREEN;
            for (DWORD i = 0; i < hashLen; ++i)
                std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)hash[i];
            std::cout << ANSI_RESET << std::dec << "\n";
        } else {
            std::cerr << ANSI_RED << "CryptGetHashParam failed for " << alg.name << "\n" << ANSI_RESET;
        }

        CryptDestroyHash(hHash);
    }

    std::ifstream crcfile(filename, std::ios::binary);
    uint32_t crc = 0xFFFFFFFF;
    unsigned char b;
    while (crcfile.read(reinterpret_cast<char*>(&b), 1)) {
        crc ^= b;
        for (int i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    crc ^= 0xFFFFFFFF;

    std::cout << ANSI_CYAN << "CRC32  " << ANSI_RESET << ": " << ANSI_GREEN << std::hex << std::uppercase
              << std::setw(8) << std::setfill('0') << crc << ANSI_RESET << std::dec << "\n";

    CryptReleaseContext(hProv, 0);
}

struct Job {
    int jobId;
    DWORD pid;         
    std::string command;
    std::string status;  
};

std::vector<Job> g_jobs; 
int g_nextJobId = 1;

void CmdJobs(const std::string& args) {
    if (g_jobs.empty()) {
        std::cout << "No background jobs.\n";
        return;
    }

    std::cout << "Jobs:\n";
    std::cout << "ID\tPID\tStatus\t\tCommand\n";
    std::cout << "-------------------------------------------\n";

    for (const auto& job : g_jobs) {
        std::cout << job.jobId << "\t"
                  << job.pid << "\t"
                  << job.status << "\t\t"
                  << job.command << "\n";
    }
}

bool ResumeProcessThreads(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return false;
    }

    bool resumedAny = false;

    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                while (ResumeThread(hThread) > 0) {
                    resumedAny = true;
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return resumedAny;
}

void CmdBgJob(const std::string& args) {
    if (args.empty()) {
        std::cerr << "Usage: bg <jobId>\n";
        return;
    }

    int jobId = std::stoi(args);

    auto it = std::find_if(g_jobs.begin(), g_jobs.end(), [jobId](const Job& job) {
        return job.jobId == jobId;
    });

    if (it == g_jobs.end()) {
        std::cerr << "Job " << jobId << " not found.\n";
        return;
    }

    if (it->status != "Stopped") {
        std::cerr << "Job " << jobId << " is not stopped.\n";
        return;
    }

    if (ResumeProcessThreads(it->pid)) {
        it->status = "Running";
        std::cout << "Job " << jobId << " resumed in background.\n";
    } else {
        std::cerr << "Failed to resume job " << jobId << ".\n";
    }
}

bool SuspendProcessThreads(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te32{ sizeof(te32) };
    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return false;
    }

    bool suspendedAny = false;
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                SuspendThread(hThread);
                suspendedAny = true;
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return suspendedAny;
}

void CmdStopJob(const std::string& args) {
    if (args.empty()) {
        std::cerr << "Usage: stop <jobId>\n";
        return;
    }

    int jobId = std::stoi(args);

    auto it = std::find_if(g_jobs.begin(), g_jobs.end(), [jobId](const Job& job) {
        return job.jobId == jobId;
    });

    if (it == g_jobs.end()) {
        std::cerr << "Job " << jobId << " not found.\n";
        return;
    }

    if (it->status == "Stopped") {
        std::cerr << "Job " << jobId << " is already stopped.\n";
        return;
    }

    if (SuspendProcessThreads(it->pid)) {
        it->status = "Stopped";
        std::cout << "Job " << jobId << " stopped.\n";
    } else {
        std::cerr << "Failed to stop job " << jobId << ".\n";
    }
}

void CmdFgJob(const std::string& args) {
    if (args.empty()) {
        std::cerr << "Usage: fg <jobId>\n";
        return;
    }

    int jobId = std::stoi(args);

    auto it = std::find_if(g_jobs.begin(), g_jobs.end(), [jobId](const Job& job) {
        return job.jobId == jobId;
    });

    if (it == g_jobs.end()) {
        std::cerr << "Job " << jobId << " not found.\n";
        return;
    }

    if (it->status == "Stopped") {
        if (!ResumeProcessThreads(it->pid)) {
            std::cerr << "Failed to resume job " << jobId << ".\n";
            return;
        }
        it->status = "Running";
    }

    std::cout << "Bringing job " << jobId << " to foreground. When done, restart Zephyr.\n";

    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, it->pid);
    if (hProcess) {
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
        it->status = "Done";
        std::cout << "Job " << jobId << " finished.\n";
    } else {
        std::cerr << "Failed to open process handle.\n";
    }
}

bool StartProcess(const std::string& command, DWORD& pid) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    std::string cmd = command;
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        return false;
    }

    pid = pi.dwProcessId;
    ResumeThread(pi.hThread); 
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

void CmdStartJob(const std::string& args) {
    if (args.empty()) {
        std::cerr << "Usage: startjob <command>\n";
        return;
    }

DWORD pid;
if (StartProcess(args, pid)) {
    static int nextJobId = 1;
    g_jobs.push_back(Job{
        nextJobId++, 
        pid,         
        "Running",  
        args        
    });
    std::cout << "Started job " << g_jobs.back().jobId << " with PID " << pid << ".\n";
} else {
    std::cerr << "Failed to start job: " << args << "\n";
    }
}

void CmdMounts(const std::string&) {
    HANDLE hFind = FindFirstVolumeA(nullptr, 0);
    char volumeName[MAX_PATH];

    hFind = FindFirstVolumeA(volumeName, ARRAYSIZE(volumeName));
    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to enumerate volumes.\n";
        return;
    }

    std::cout << "\033[1;36mMounted Volumes:\033[0m\n";

    do {
        DWORD charCount = 0;
        GetVolumePathNamesForVolumeNameA(volumeName, nullptr, 0, &charCount);
        std::vector<char> names(charCount);
        if (!GetVolumePathNamesForVolumeNameA(volumeName, names.data(), charCount, &charCount)) {
            continue;
        }

        std::string paths;
        for (DWORD i = 0; i < charCount; ) {
            std::string path(&names[i]);
            if (!path.empty()) {
                if (!paths.empty()) paths += ", ";
                paths += path;
            }
            i += path.length() + 1;
        }
        if (paths.empty()) paths = "—";

        char label[MAX_PATH] = {}, fsName[MAX_PATH] = {};
        DWORD serialNumber, maxCompLen, fsFlags;
        GetVolumeInformationA(volumeName, label, MAX_PATH, &serialNumber, &maxCompLen, &fsFlags, fsName, MAX_PATH);

        ULARGE_INTEGER total, free, avail;
        bool spaceOk = GetDiskFreeSpaceExA(paths != "—" ? paths.c_str() : volumeName, &avail, &total, &free);

        std::cout << "\n\033[1;33m" << volumeName << "\033[0m\n";
        std::cout << "  Mount Points: " << paths << "\n";
        std::cout << "  Label: " << (label[0] ? label : "N/A") << "\n";
        std::cout << "  FS: " << (fsName[0] ? fsName : "N/A");

        if (spaceOk) {
            double gb = 1024.0 * 1024 * 1024;
            double used = (total.QuadPart - free.QuadPart) / gb;
            double size = total.QuadPart / gb;
            std::cout << ", Used: " << std::fixed << std::setprecision(1) << used << " GB / " << size << " GB";
        }

        std::cout << "\n";

    } while (FindNextVolumeA(hFind, volumeName, ARRAYSIZE(volumeName)));

    FindVolumeClose(hFind);
}

void CmdFMeta(const std::string& args) {
    std::istringstream iss(args);
    std::string file_path;
    if (!(iss >> file_path)) {
        std::cout << "Usage: fmeta <file_path>\n";
        return;
    }

    fs::path path(file_path);

    if (!fs::exists(path)) {
        std::cout << "File does not exist: " << file_path << "\n";
        return;
    }

    if (!fs::is_regular_file(path)) {
        std::cout << "Not a regular file: " << file_path << "\n";
        return;
    }

    std::cout << "File: " << path << "\n";
    std::cout << "Size: " << fs::file_size(path) << " bytes\n";

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExA(file_path.c_str(), GetFileExInfoStandard, &fileInfo)) {
        std::cout << "Failed to get file attributes.\n";
        return;
    }

    auto FileTimeToString = [](const FILETIME& ft) -> std::string {
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&ft, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
                 stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                 stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        return std::string(buffer);
    };

    std::cout << "Created:       " << FileTimeToString(fileInfo.ftCreationTime) << "\n";
    std::cout << "Last Accessed: " << FileTimeToString(fileInfo.ftLastAccessTime) << "\n";
    std::cout << "Last Modified: " << FileTimeToString(fileInfo.ftLastWriteTime) << "\n";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cout << "CryptAcquireContext failed.\n";
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cout << "CryptCreateHash failed.\n";
        CryptReleaseContext(hProv, 0);
        return;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cout << "Failed to open file for hashing.\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), (DWORD)file.gcount(), 0)) {
            std::cout << "CryptHashData failed.\n";
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return;
        }
    }

    BYTE hash[32];
    DWORD hashLen = 32;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        std::cout << "SHA256:        ";
        for (DWORD i = 0; i < hashLen; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        std::cout << std::dec << "\n";
    } else {
        std::cout << "Failed to get hash value.\n";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void CmdRamInfo(const std::string& args) {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);

    if (!GlobalMemoryStatusEx(&memStatus)) {
        std::cerr << ANSI_RED << "Failed to retrieve memory information.\n" << ANSI_RESET;
        return;
    }

    auto toMB = [](SIZE_T bytes) { return bytes / (1024 * 1024); };
    auto toGB = [](SIZE_T bytes) { return bytes / (1024.0 * 1024.0 * 1024.0); };

    auto printSection = [=](const std::string& title, DWORDLONG total, DWORDLONG avail, DWORDLONG used) {
        std::cout << ANSI_YELLOW << ">> " << title << "\n" << ANSI_RESET;
        std::cout << "  Total     : " << toMB(total) << " MB (" << std::fixed << std::setprecision(2) << toGB(total) << " GB)\n";
        std::cout << "  Available : " << toMB(avail) << " MB (" << std::fixed << std::setprecision(2) << toGB(avail) << " GB)\n";
        std::cout << "  Used      : " << toMB(used) << " MB (" << std::fixed << std::setprecision(2) << toGB(used) << " GB)\n";
    };

    DWORDLONG totalPhys = memStatus.ullTotalPhys;
    DWORDLONG availPhys = memStatus.ullAvailPhys;
    DWORDLONG usedPhys = totalPhys - availPhys;

    DWORDLONG totalPage = memStatus.ullTotalPageFile;
    DWORDLONG availPage = memStatus.ullAvailPageFile;
    DWORDLONG usedPage = totalPage - availPage;

    DWORDLONG totalVirt = memStatus.ullTotalVirtual;
    DWORDLONG availVirt = memStatus.ullAvailVirtual;
    DWORDLONG usedVirt = totalVirt - availVirt;

    DWORDLONG totalExt = memStatus.ullAvailExtendedVirtual;

    std::cout << ANSI_CYAN << "=== RAM Information ===\n" << ANSI_RESET;

    printSection("Physical Memory (RAM)", totalPhys, availPhys, usedPhys);
    printSection("Page File (Swap on Disk)", totalPage, availPage, usedPage);

    std::cout << ANSI_YELLOW << ">> Virtual Address Space (User-Mode Limit on 64-bit)\n" << ANSI_RESET;
    std::cout << "  Total     : " << toMB(totalVirt) << " MB (" << std::fixed << std::setprecision(2) << toGB(totalVirt) << " GB)\n";
    std::cout << "  Available : " << toMB(availVirt) << " MB (" << std::fixed << std::setprecision(2) << toGB(availVirt) << " GB)\n";
    std::cout << "  Used      : " << toMB(usedVirt) << " MB (" << std::fixed << std::setprecision(2) << toGB(usedVirt) << " GB)\n";

    std::cout << ANSI_YELLOW << ">> Load:\n" << ANSI_RESET;
    std::cout << "  Memory Load: " << std::fixed << std::setprecision(2) << (double)memStatus.dwMemoryLoad << " %\n";

    std::cout << ANSI_YELLOW << ">> Extended Virtual (Reserved - usually zero):\n" << ANSI_RESET;
    std::cout << "  Available : " << toMB(totalExt) << " MB (" << std::fixed << std::setprecision(2) << toGB(totalExt) << " GB)\n";

    PERFORMANCE_INFORMATION perfInfo;
    if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
        std::cout << ANSI_YELLOW << ">> Performance Info (Pages):\n" << ANSI_RESET;
        std::cout << "  Commit Total      : " << perfInfo.CommitTotal << " pages\n";
        std::cout << "  Commit Limit      : " << perfInfo.CommitLimit << " pages\n";
        std::cout << "  Commit Peak       : " << perfInfo.CommitPeak << " pages\n";
        std::cout << "  Physical Total    : " << perfInfo.PhysicalTotal << " pages\n";
        std::cout << "  Physical Available: " << perfInfo.PhysicalAvailable << " pages\n";
        std::cout << "  System Cache      : " << perfInfo.SystemCache << " pages\n";
    }
}


void CmdLsusb(const std::string& args) {
    if (!args.empty()) {
        std::cout << "Usage: lsusb" << std::endl;
        return;
    }

    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(&GUID_DEVINTERFACE_USB_DEVICE, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to get USB device list." << std::endl;
        return;
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData = {};
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    std::cout << "Connected USB Devices:\n";

    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, nullptr, &GUID_DEVINTERFACE_USB_DEVICE, i, &deviceInterfaceData); ++i) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, nullptr, 0, &requiredSize, nullptr);

        std::vector<BYTE> detailDataBuffer(requiredSize);
        auto pDetailData = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(detailDataBuffer.data());
        pDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        SP_DEVINFO_DATA devInfoData = {};
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        if (!SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, pDetailData, requiredSize, nullptr, &devInfoData)) {
            std::cout << "Failed to get device details." << std::endl;
            continue;
        }

        wchar_t deviceName[256];
        if (!SetupDiGetDeviceRegistryProperty(deviceInfoSet, &devInfoData, SPDRP_DEVICEDESC, nullptr, (PBYTE)deviceName, sizeof(deviceName), nullptr)) {
            wcscpy_s(deviceName, 256, L"<Unknown USB Device>");
        }

        wchar_t hardwareId[256];
        if (!SetupDiGetDeviceRegistryProperty(deviceInfoSet, &devInfoData, SPDRP_HARDWAREID, nullptr, (PBYTE)hardwareId, sizeof(hardwareId), nullptr)) {
            wcscpy_s(hardwareId, L"<Unknown ID>");
        }

        std::wcout << L" - " << deviceName << L" [" << hardwareId << L"]\n";
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
}

void CmdWc(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    std::vector<std::string> flags;

    std::string token;
    while (iss >> token) {
        if (token[0] == '-') {
            flags.push_back(token);
        } else {
            filename = token;
        }
    }

    if (filename.empty()) {
        std::cout << "Usage: wc <file> [-l] [-w] [-c] [-m] [-L]" << std::endl;
        return;
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cout << "Cannot open file: " << filename << std::endl;
        return;
    }

    size_t lines = 0, words = 0, bytes = 0, chars = 0, maxLineLen = 0;
    std::string line;

    while (std::getline(file, line)) {
        ++lines;
        words += std::count_if(line.begin(), line.end(), [](char c) { return std::isspace(c); }) + 1;
        chars += line.size();
        bytes += line.size() + 1; 
        maxLineLen = std::max(maxLineLen, line.size()); 
    }

    if (flags.empty()) {
        std::cout << "Lines: " << lines << "\nWords: " << words
        << "\nBytes: " << bytes << "\nCharacters: " << chars
        << "\nLongest line: " << maxLineLen << std::endl;
        return;
    }

    for (const auto& flag : flags) {
        if (flag == "-l") std::cout << "Lines: " << lines << std::endl;
        else if (flag == "-w") std::cout << "Words: " << words << std::endl;
        else if (flag == "-c") std::cout << "Bytes: " << bytes << std::endl;
        else if (flag == "-m") std::cout << "Characters: " << chars << std::endl;
        else if (flag == "-L") std::cout << "Longest line length: " << maxLineLen << std::endl;
        else std::cout << "Unknown flag: " << flag << std::endl;
    }
}

void CmdGzip(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    iss >> filename;

    if (filename.empty()) {
        std::cout << "Usage: gzip <file>" << std::endl;
        return;
    }

    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        std::cout << "Cannot open input file: " << filename << std::endl;
        return;
    }

    std::string outFilename = filename + ".gz";
    gzFile outFile = gzopen(outFilename.c_str(), "wb");
    if (!outFile) {
        std::cout << "Failed to open output file: " << outFilename << std::endl;
        return;
    }

    char buffer[4096];
    while (inFile.read(buffer, sizeof(buffer)) || inFile.gcount()) {
        gzwrite(outFile, buffer, static_cast<unsigned int>(inFile.gcount()));
    }

    inFile.close();
    gzclose(outFile);

    std::cout << "Compressed \"" << filename << "\" to \"" << outFilename << "\"" << std::endl;
}

void CmdGunzip(const std::string& args) {
    std::istringstream iss(args);
    std::string gzFilename;
    iss >> gzFilename;

    if (gzFilename.empty()) {
        std::cout << "Usage: gunzip <file.gz>" << std::endl;
        return;
    }

    if (gzFilename.size() < 4 || gzFilename.substr(gzFilename.size() - 3) != ".gz") {
        std::cout << "Error: Input file must end with .gz" << std::endl;
        return;
    }

    std::string outFilename = gzFilename.substr(0, gzFilename.size() - 3);

    gzFile inFile = gzopen(gzFilename.c_str(), "rb");
    if (!inFile) {
        std::cout << "Cannot open compressed file: " << gzFilename << std::endl;
        return;
    }

    std::ofstream outFile(outFilename, std::ios::binary);
    if (!outFile) {
        std::cout << "Failed to create output file: " << outFilename << std::endl;
        gzclose(inFile);
        return;
    }

    char buffer[4096];
    int bytesRead;
    while ((bytesRead = gzread(inFile, buffer, sizeof(buffer))) > 0) {
        outFile.write(buffer, bytesRead);
    }

    gzclose(inFile);
    outFile.close();

    std::cout << "Decompressed \"" << gzFilename << "\" to \"" << outFilename << "\"" << std::endl;
}

void CmdZip(const std::string& args) {
    std::istringstream iss(args);
    std::string srcFile, zipFile;
    iss >> srcFile >> zipFile;

    if (srcFile.empty() || zipFile.empty()) {
        std::cout << "Usage: zip <sourcefile> <zipfile>" << std::endl;
        return;
    }

    if (!std::filesystem::exists(srcFile)) {
        std::cout << "Error: Source file does not exist." << std::endl;
        return;
    }

    std::string command = "powershell -Command \"Compress-Archive -Path \\\"" + srcFile + "\\\" -DestinationPath \\\"" + zipFile + "\\\" -Force\"";

    int result = std::system(command.c_str());

    if (result == 0) {
        std::cout << "Zipped \"" << srcFile << "\" to \"" << zipFile << "\"" << std::endl;
    } else {
        std::cout << "Error: Failed to zip file with PowerShell." << std::endl;
    }
}

void CmdUnzip(const std::string& args) {
    std::istringstream iss(args);
    std::string zipFile, outputDir;
    iss >> zipFile >> outputDir;

    if (zipFile.empty()) {
        std::cout << "Usage: unzip <zipfile> [output_dir]" << std::endl;
        return;
    }

    if (!std::filesystem::exists(zipFile)) {
        std::cout << "Error: Zip file does not exist." << std::endl;
        return;
    }

    if (outputDir.empty()) {
        outputDir = std::filesystem::current_path().string();
    }

    std::string command = "powershell -Command \"Expand-Archive -Path \\\"" + zipFile + "\\\" -DestinationPath \\\"" + outputDir + "\\\" -Force\"";

    int result = std::system(command.c_str());

    if (result == 0) {
        std::cout << "Unzipped \"" << zipFile << "\" to \"" << outputDir << "\"" << std::endl;
    } else {
        std::cout << "Error: Failed to unzip file with PowerShell." << std::endl;
    }
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

std::wstring WCharToWString(const wchar_t* wstr) {
    return std::wstring(wstr ? wstr : L"");
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

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &pe)) {
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
        info.name = WCharToWString(pe.szExeFile); 
        info.memMB = memUsage;
        processes.push_back(info);

    } while (Process32NextW(snapshot, &pe));

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

void PrintFeature(const std::string& name, bool supported) {
    std::cout << "  " << std::left << std::setw(10) << name << ": ";
    std::cout << (supported ? ANSI_BOLD_GREEN "Yes" ANSI_RESET : ANSI_BOLD_RED "No" ANSI_RESET) << std::endl;
}

void CmdCpuInfo(const std::string& args) {
    if (!args.empty()) {
        std::cout << ANSI_BOLD_RED "Usage: cpuinfo" ANSI_RESET << std::endl;
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

    int cpuInfo[4] = {};
    char brand[0x40] = {};
    __cpuid(cpuInfo, 0x80000002);
    memcpy(brand, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000003);
    memcpy(brand + 16, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000004);
    memcpy(brand + 32, cpuInfo, sizeof(cpuInfo));

    int vendor[4] = {};
    __cpuid(vendor, 0);
    char vendorId[13] = {};
    *reinterpret_cast<int*>(vendorId) = vendor[1];      
    *reinterpret_cast<int*>(vendorId + 4) = vendor[3];  
    *reinterpret_cast<int*>(vendorId + 8) = vendor[2];  

    __cpuid(cpuInfo, 1);
    int family = ((cpuInfo[0] >> 8) & 0xf) + ((cpuInfo[0] >> 20) & 0xff);
    int model = ((cpuInfo[0] >> 4) & 0xf) + (((cpuInfo[0] >> 16) & 0xf) << 4);
    int stepping = cpuInfo[0] & 0xf;

    std::cout << ANSI_BOLD_CYAN "==================== CPU Information ====================" ANSI_RESET << std::endl;
    std::cout << "CPU Name: " << brand << std::endl;
    std::cout << "Vendor ID: " << vendorId << std::endl;
    std::cout << "Family: " << family << ", Model: " << model << ", Stepping: " << stepping << std::endl;

    std::cout << "Architecture: ";
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: std::cout << "x64 (AMD or Intel)"; break;
        case PROCESSOR_ARCHITECTURE_ARM: std::cout << "ARM"; break;
        case PROCESSOR_ARCHITECTURE_IA64: std::cout << "Intel Itanium"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: std::cout << "x86"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;

    std::cout << "Hyper-Threading: " << ((cpuInfo[3] & (1 << 28)) ? "Supported" : "Not Supported") << std::endl;
    std::cout << "CPU Frequency: " << (freq ? std::to_string(freq) + " MHz" : "Unknown") << std::endl;
    std::cout << "NUMA Nodes: " << sysInfo.dwNumberOfProcessors << std::endl;
    std::cout << "Page Size: " << sysInfo.dwPageSize << " bytes" << std::endl;
    std::cout << "Active Processor Mask: 0x" << std::hex << sysInfo.dwActiveProcessorMask << std::dec << std::endl;
    std::cout << "Physical cores: " << physicalCoreCount << std::endl;
    std::cout << "Logical processors: " << logicalCount << std::endl;

    std::cout << ANSI_BOLD_MAGENTA "Cache Sizes:" ANSI_RESET << std::endl;
    std::cout << "  L1 Cache: " << (L1 ? std::to_string(L1 / 1024) + " KB" : "Unknown") << std::endl;
    std::cout << "  L2 Cache: " << (L2 ? std::to_string(L2 / 1024) + " KB" : "Unknown") << std::endl;
    std::cout << "  L3 Cache: " << (L3 ? std::to_string(L3 / 1024) + " KB" : "Unknown") << std::endl;

    std::cout << ANSI_BOLD_CYAN "\nSupported Instruction Sets:\n" ANSI_RESET;

    bool sse41 = (cpuInfo[2] & (1 << 19));
    bool sse42 = (cpuInfo[2] & (1 << 20));
    bool avx   = (cpuInfo[2] & (1 << 28));
    bool fma   = (cpuInfo[2] & (1 << 12));
    bool aes   = (cpuInfo[2] & (1 << 25));
    bool rdrand = (cpuInfo[2] & (1 << 30));

    __cpuid(cpuInfo, 7);
    bool avx2  = (cpuInfo[1] & (1 << 5));
    bool bmi1  = (cpuInfo[1] & (1 << 3));
    bool bmi2  = (cpuInfo[1] & (1 << 8));
    bool avx512f = (cpuInfo[1] & (1 << 16));
    bool sha   = (cpuInfo[1] & (1 << 29));
    bool sgx   = (cpuInfo[1] & (1 << 2));

    PrintFeature("SSE4.1", sse41);
    PrintFeature("SSE4.2", sse42);
    PrintFeature("AVX",    avx);
    PrintFeature("AVX2",   avx2);
    PrintFeature("AVX-512", avx512f);
    PrintFeature("FMA",    fma);
    PrintFeature("BMI1",   bmi1);
    PrintFeature("BMI2",   bmi2);
    PrintFeature("AES-NI", aes);
    PrintFeature("RDRAND", rdrand);
    PrintFeature("SHA",    sha);
    PrintFeature("SGX",    sgx);

    std::cout << ANSI_BOLD_CYAN "=========================================================" ANSI_RESET << std::endl;
}

void CmdUserInfo(const std::string& args) {
    char username[UNLEN + 1];
    DWORD username_len = sizeof(username);
    if (!GetUserNameA(username, &username_len)) {
        std::cerr << ANSI_BOLD_RED << "Failed to get username\n" << ANSI_RESET;
        return;
    }

    char domainname[DNLEN + 1];
    DWORD domain_len = sizeof(domainname);
    SID_NAME_USE sidType;
    PSID pSid = nullptr;
    DWORD sidSize = 0;

    LookupAccountNameA(NULL, username, NULL, &sidSize, NULL, &domain_len, &sidType);
    pSid = (PSID)malloc(sidSize);
    if (!LookupAccountNameA(NULL, username, pSid, &sidSize, domainname, &domain_len, &sidType)) {
        std::cerr << ANSI_BOLD_RED << "Failed to lookup account name\n" << ANSI_RESET;
        free(pSid);
        return;
    }

    LPSTR sidString = nullptr;
    if (!ConvertSidToStringSidA(pSid, &sidString)) {
        sidString = nullptr;
    }

    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        std::cerr << ANSI_BOLD_RED << "Failed to open process token\n" << ANSI_RESET;
        free(pSid);
        if (sidString) LocalFree(sidString);
        return;
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(token, TokenGroups, NULL, 0, &tokenInfoLength);
    std::vector<BYTE> tokenInfoBuffer(tokenInfoLength);

    if (!GetTokenInformation(token, TokenGroups, tokenInfoBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
        std::cerr << ANSI_BOLD_RED << "Failed to get token groups\n" << ANSI_RESET;
        CloseHandle(token);
        free(pSid);
        if (sidString) LocalFree(sidString);
        return;
    }

    TOKEN_GROUPS* groups = (TOKEN_GROUPS*)tokenInfoBuffer.data();

    std::cout << ANSI_BOLD_BLUE << "\n=== User Information ===" << ANSI_RESET << "\n";
    std::cout << ANSI_BOLD_GREEN << "Username       : " << ANSI_RESET << username << "\n";
    std::cout << ANSI_BOLD_GREEN << "Domain         : " << ANSI_RESET << domainname << "\n";
    std::cout << ANSI_BOLD_GREEN << "User SID       : " << ANSI_RESET << (sidString ? sidString : "N/A") << "\n";

    std::cout << ANSI_BOLD_YELLOW << "Groups         :" << ANSI_RESET << "\n";
    for (DWORD i = 0; i < groups->GroupCount; i++) {
        SID_NAME_USE use;
        char groupName[256], groupDomain[256];
        DWORD groupNameLen = sizeof(groupName);
        DWORD groupDomainLen = sizeof(groupDomain);

        if (LookupAccountSidA(NULL, groups->Groups[i].Sid, groupName, &groupNameLen, groupDomain, &groupDomainLen, &use)) {
            std::cout << "  - " << ANSI_CYAN << groupDomain << "\\" << groupName << ANSI_RESET << "\n";
        }
        else {
            std::cout << "  - " << ANSI_RED << "Unknown Group" << ANSI_RESET << "\n";
        }
    }

    DWORD privSize = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &privSize);
    std::vector<BYTE> privBuffer(privSize);

    if (GetTokenInformation(token, TokenPrivileges, privBuffer.data(), privSize, &privSize)) {
        TOKEN_PRIVILEGES* privs = (TOKEN_PRIVILEGES*)privBuffer.data();
        std::cout << ANSI_BOLD_YELLOW << "Privileges    :" << ANSI_RESET << "\n";
        for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
            LUID_AND_ATTRIBUTES& la = privs->Privileges[i];
            char name[256];
            DWORD nameLen = sizeof(name);
            if (LookupPrivilegeNameA(NULL, &la.Luid, name, &nameLen)) {
                std::cout << "  - " << ANSI_MAGENTA << name << ANSI_RESET << "\n";
            }
        }
    }

    char* homeDir = getenv("USERPROFILE");
    std::cout << ANSI_BOLD_GREEN << "Home Directory : " << ANSI_RESET << (homeDir ? homeDir : "N/A") << "\n";

    char profileDir[MAX_PATH];
    DWORD profileLen = MAX_PATH;
    if (GetUserProfileDirectoryA(token, profileDir, &profileLen)) {
        std::cout << ANSI_BOLD_GREEN << "Profile Dir    : " << ANSI_RESET << profileDir << "\n";
    }
    else {
        std::cout << ANSI_BOLD_GREEN << "Profile Dir    : " << ANSI_RESET << "N/A\n";
    }

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    WTS_CONNECTSTATE_CLASS* pState = nullptr;
    DWORD bytesReturned = 0;
    if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSConnectState, (LPSTR*)&pState, &bytesReturned)) {
        std::cout << ANSI_BOLD_GREEN << "Session Type  : " << ANSI_RESET;
        switch (*pState) {
            case WTSActive: std::cout << "Active\n"; break;
            case WTSConnected: std::cout << "Connected\n"; break;
            case WTSConnectQuery: std::cout << "ConnectQuery\n"; break;
            case WTSShadow: std::cout << "Shadow\n"; break;
            case WTSDisconnected: std::cout << "Disconnected\n"; break;
            case WTSIdle: std::cout << "Idle\n"; break;
            case WTSListen: std::cout << "Listen\n"; break;
            case WTSReset: std::cout << "Reset\n"; break;
            case WTSDown: std::cout << "Down\n"; break;
            case WTSInit: std::cout << "Init\n"; break;
            default: std::cout << "Unknown\n"; break;
        }
        WTSFreeMemory(pState);
    }
    else {
        std::cout << ANSI_BOLD_GREEN << "Session Type  : " << ANSI_RESET << "Unknown\n";
    }

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD compLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &compLen)) {
        std::cout << ANSI_BOLD_GREEN << "Machine Name  : " << ANSI_RESET << computerName << "\n";
    }

    CloseHandle(token);
    free(pSid);
    if (sidString) LocalFree(sidString);
}

void CmdWhoAmI(const std::string& args) {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserNameA(username, &username_len)) {
        std::cout << "Username: " << username << "\n";
    } else {
        std::cerr << "Failed to get username.\n";
        return;
    }

    if (args != "-ext")
        return;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token.\n";
        return;
    }

    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buffer(len);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), len, &len)) {
        std::cerr << "Failed to get token info.\n";
        CloseHandle(hToken);
        return;
    }

    PSID sid = reinterpret_cast<PTOKEN_USER>(buffer.data())->User.Sid;
    LPSTR sidStr = nullptr;
    if (ConvertSidToStringSidA(sid, &sidStr)) {
        std::cout << "SID: " << sidStr << "\n";
        LocalFree(sidStr);
    } else {
        std::cerr << "Failed to convert SID.\n";
    }

    len = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &len);
    std::vector<BYTE> levelBuffer(len);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, levelBuffer.data(), len, &len)) {
        PTOKEN_MANDATORY_LABEL pLabel = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(levelBuffer.data());
        DWORD level = *GetSidSubAuthority(pLabel->Label.Sid, 0);

        std::string integrity;
        if (level == SECURITY_MANDATORY_LOW_RID)
            integrity = "Low";
        else if (level >= SECURITY_MANDATORY_MEDIUM_RID && level < SECURITY_MANDATORY_HIGH_RID)
            integrity = "Medium";
        else if (level >= SECURITY_MANDATORY_HIGH_RID && level < SECURITY_MANDATORY_SYSTEM_RID)
            integrity = "High";
        else if (level >= SECURITY_MANDATORY_SYSTEM_RID)
            integrity = "System";

        std::cout << "Integrity Level: " << integrity << "\n";
    } else {
        std::cerr << "Failed to get integrity level.\n";
    }

    BOOL isAdmin = FALSE;
    CheckTokenMembership(nullptr, (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE), &isAdmin);
    std::cout << "Admin: " << (IsUserAnAdmin() ? "Yes" : "No") << "\n";

    CloseHandle(hToken);
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

void SecureOverwriteFile(const std::string& filename, int passes, bool useRandom)
{
    HANDLE hFile = CreateFileA(filename.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error: Cannot open file for wiping: " << filename << "\n";
        return;
    }

    LARGE_INTEGER filesize;
    if (!GetFileSizeEx(hFile, &filesize))
    {
        std::cerr << "Error: Cannot get file size: " << filename << "\n";
        CloseHandle(hFile);
        return;
    }

    std::cout << "Wiping file: " << filename << " (" << filesize.QuadPart << " bytes), Passes: " << passes << "\n";

    const size_t bufSize = 64 * 1024;
    std::vector<char> buffer(bufSize);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int pass = 1; pass <= passes; ++pass)
    {
        std::cout << "Pass " << pass << " of " << passes << "...\n";
        LARGE_INTEGER pos; pos.QuadPart = 0;
        if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN))
        {
            std::cerr << "Error: Failed to seek start of file\n";
            CloseHandle(hFile);
            return;
        }

        LONGLONG bytesLeft = filesize.QuadPart;
        while (bytesLeft > 0)
        {
            size_t chunk = (bytesLeft > (LONGLONG)bufSize) ? bufSize : (size_t)bytesLeft;

            if (useRandom)
            {
                for (size_t i = 0; i < chunk; ++i)
                    buffer[i] = (char)dis(gen);
            }
            else
            {
                memset(buffer.data(), 0, chunk);
            }

            DWORD written = 0;
            if (!WriteFile(hFile, buffer.data(), (DWORD)chunk, &written, nullptr) || written != chunk)
            {
                std::cerr << "Error: Write failed during wiping\n";
                CloseHandle(hFile);
                return;
            }

            bytesLeft -= chunk;
        }

        FlushFileBuffers(hFile);
    }

    CloseHandle(hFile);

    if (DeleteFileA(filename.c_str()))
    {
        std::cout << "File securely wiped and deleted successfully.\n";
    }
    else
    {
        std::cerr << "Error: Could not delete the file after wiping.\n";
    }
}

void CmdFZap(const std::string& args)
{
    std::istringstream iss(args);
    std::vector<std::string> tokens;
    for (std::string token; iss >> token;)
        tokens.push_back(token);

    if (tokens.empty())
    {
        std::cout << "Usage: fzap <filename> [passes] [zero|random]\n";
        return;
    }

    std::string filename = tokens[0];
    int passes = 3;  
    bool useRandom = false;

    if (tokens.size() > 1)
    {
        try
        {
            passes = std::stoi(tokens[1]);
            if (passes < 1) passes = 1;
            if (passes > 10) passes = 10;
        }
        catch (...)
        {
            std::cout << "Invalid number of passes, using default 3.\n";
            passes = 3;
        }
    }

    if (tokens.size() > 2)
    {
        std::string mode = tokens[2];
        for (auto& c : mode) c = (char)tolower(c);
        if (mode == "random")
            useRandom = true;
        else if (mode == "zero")
            useRandom = false;
        else
            std::cout << "Unknown mode '" << tokens[2] << "'. Use 'zero' or 'random'. Defaulting to zero.\n";
    }

    SecureOverwriteFile(filename, passes, useRandom);
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

    RunBatchIfExists(cmd, args);
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
    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORYSTATUSEX msx{ sizeof(msx) }; GlobalMemoryStatusEx(&msx);
    auto bytesToGB = [](DWORDLONG b){ return b / 1024.0 / 1024 / 1024; };

    const char* L = "\033[1;33m";
    const char* V = "\033[1;36m";
    const char* R = "\033[0m";

    std::cout << L << "CPU cores (logical): " << V << si.dwNumberOfProcessors << R << "\n";
    std::cout << L << "Processor type: " << V << si.dwProcessorType << R << "\n";
    std::cout << L << "Processor arch: " << V;
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: std::cout << "x64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: std::cout << "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM: std::cout << "ARM"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: std::cout << "ARM64"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << R << "\n";
    std::cout << L << "Processor level: " << V << si.wProcessorLevel << R << "\n";
    std::cout << L << "Processor revision: " << V
              << (si.wProcessorRevision >> 8) << "." << (si.wProcessorRevision & 0xFF) << R << "\n";
    std::cout << L << "Page size: " << V << si.dwPageSize << " bytes" << R << "\n";
    std::cout << L << "Allocation granularity: " << V << si.dwAllocationGranularity << " bytes" << R << "\n";
    std::cout << L << "Min app addr: " << V << si.lpMinimumApplicationAddress << R << "\n";
    std::cout << L << "Max app addr: " << V << si.lpMaximumApplicationAddress << R << "\n";
    std::cout << L << "Active processor mask: " << V << "0x" << std::hex << si.dwActiveProcessorMask
              << std::dec << R << "\n";

    std::cout << L << "Total physical memory: " << V << std::fixed << std::setprecision(2)
              << bytesToGB(msx.ullTotalPhys) << " GB" << R << "\n";
    std::cout << L << "Available physical memory: " << V << bytesToGB(msx.ullAvailPhys) << " GB" << R << "\n";
    std::cout << L << "Total virtual memory: " << V << bytesToGB(msx.ullTotalVirtual) << " GB" << R << "\n";
    std::cout << L << "Available virtual memory: " << V << bytesToGB(msx.ullAvailVirtual) << " GB" << R << "\n";
    std::cout << L << "Memory load: " << V;
    int load = msx.dwMemoryLoad;
    std::cout << ((load >= 60) ? "\033[1;31m" : (load >= 40) ? "\033[1;33m" : "\033[1;32m")
              << load << "%" << R << "\n";

    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return;
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    IWbemLocator* locator = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, (LPVOID*)&locator))) {
        CoUninitialize(); return;
    }

    IWbemServices* svc = nullptr;
    locator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);

    auto query = [&](const wchar_t* wql, auto&& fn) {
        IEnumWbemClassObject* ent = nullptr;
        if (SUCCEEDED(svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql),
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                     nullptr, &ent))) {
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            while (ent && SUCCEEDED(ent->Next(WBEM_INFINITE, 1, &obj, &ret)) && ret) {
                fn(obj);
                obj->Release();
            }
            ent->Release();
        }
    };

    auto getProp = [&](IWbemClassObject* o, LPCWSTR p, const char* label) {
        VARIANT v;
        if (SUCCEEDED(o->Get(p, 0, &v, 0, 0)) && v.vt != VT_NULL && v.vt != VT_EMPTY) {
            if (v.vt == VT_BSTR)
                std::wcout << L << label << V << static_cast<const wchar_t*>(_bstr_t(v.bstrVal)) << R << L"\n";
            else if (v.vt == VT_I4)
                std::cout << L << label << V << v.intVal << R << "\n";
            else if (v.vt == VT_UI4)
                std::cout << L << label << V << v.uintVal << R << "\n";
        }
        VariantClear(&v);
    };

    OSVERSIONINFOEXW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExW(reinterpret_cast<LPOSVERSIONINFOW>(&osvi));
    std::cout << L << "Win version (major.minor.build): " << V
              << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
              << " (Build " << osvi.dwBuildNumber << ")" << R << "\n";
    std::cout << L << "Service Pack: " << V
              << (osvi.szCSDVersion[0] ? osvi.szCSDVersion : L"None") << R << "\n";
    std::cout << L << "Suite mask: " << V << osvi.wSuiteMask << R << "\n";
    std::cout << L << "Product type: " << V;
    switch(osvi.wProductType) {
        case VER_NT_WORKSTATION: std::cout << "Workstation"; break;
        case VER_NT_SERVER: std::cout << "Server"; break;
        default: std::cout << "Other"; break;
    }
    std::cout << R << "\n";

    query(L"SELECT * FROM Win32_ComputerSystem", [&](IWbemClassObject* o){
        getProp(o, L"Manufacturer", "System Manufacturer: ");
        getProp(o, L"Model", "System Model: ");
        getProp(o, L"Name", "System Name: ");
        getProp(o, L"SystemType", "System Type: ");
    });

    query(L"SELECT * FROM Win32_OperatingSystem", [&](IWbemClassObject* o){
        getProp(o, L"Caption", "OS Name: ");
        getProp(o, L"Version", "OS Version: ");
        getProp(o, L"Description", "OS Description: ");
        getProp(o, L"Manufacturer", "OS Manufacturer: ");
        getProp(o, L"Locale", "Locale: ");
        getProp(o, L"WindowsDirectory", "Windows Directory: ");
        getProp(o, L"SystemDirectory", "System Directory: ");
        getProp(o, L"BootDevice", "Boot Device: ");
        getProp(o, L"InstallDate", "Install Date: ");
        getProp(o, L"LastBootUpTime", "Last Boot Time: ");
        getProp(o, L"TotalVisibleMemorySize", "Installed Physical Memory (KB): ");
        getProp(o, L"FreePhysicalMemory", "Available Physical Memory (KB): ");
        getProp(o, L"TotalVirtualMemorySize", "Total Virtual Memory (KB): ");
        getProp(o, L"FreeVirtualMemory", "Available Virtual Memory (KB): ");
        getProp(o, L"SizeStoredInPagingFiles", "Page File Size (KB): ");
        getProp(o, L"PagingFiles", "Page File (directory): ");
        getProp(o, L"SystemDirectory", "Hardware Abstraction Layer: ");
        getProp(o, L"LocalDateTime", "Time Zone: ");
        getProp(o, L"CurrentTimeZone", "Current Time Zone Offset (minutes): ");
    });

    query(L"SELECT * FROM Win32_BIOS", [&](IWbemClassObject* o){
        getProp(o, L"BIOSVersion", "BIOS Version: ");
        getProp(o, L"ReleaseDate", "BIOS Date: ");
        getProp(o, L"SMBIOSBIOSVersion", "SMBIOS Version: ");
        getProp(o, L"EmbeddedControllerMajorVersion", "Embedded Controller Version: ");
        getProp(o, L"BIOSMode", "BIOS Mode: ");
    });

    query(L"SELECT * FROM Win32_BaseBoard", [&](IWbemClassObject* o){
        getProp(o, L"Manufacturer", "BaseBoard Manufacturer: ");
        getProp(o, L"Product", "BaseBoard Product: ");
        getProp(o, L"Version", "BaseBoard Version: ");
        getProp(o, L"SerialNumber", "BaseBoard Serial Number: ");
        getProp(o, L"Model", "BaseBoard Model: ");
    });

    query(L"SELECT * FROM Win32_Processor", [&](IWbemClassObject* o){
        getProp(o, L"Name", "Processor: ");
        getProp(o, L"NumberOfCores", "Physical Cores: ");
        getProp(o, L"NumberOfLogicalProcessors", "Logical Processors: ");
        getProp(o, L"MaxClockSpeed", "Max Clock Speed (MHz): ");
        getProp(o, L"CurrentClockSpeed", "Current Clock Speed (MHz): ");
        getProp(o, L"Architecture", "Architecture: ");
        getProp(o, L"AddressWidth", "Address Width: ");
    });

    query(L"SELECT * FROM Win32_DeviceGuard", [&](IWbemClassObject* o){
        getProp(o, L"VirtualizationBasedSecurityStatus", "VBS State: ");
        getProp(o, L"RequiredSecurityProperties", "VBS Required Security Properties: ");
        getProp(o, L"AvailableSecurityProperties", "VBS Available Security Properties: ");
        getProp(o, L"SecurityServicesConfigured", "VBS Services Configured: ");
        getProp(o, L"SecurityServicesRunning", "VBS Services Running: ");
        getProp(o, L"PCR7Configuration", "PCR7 Configuration: ");
        getProp(o, L"SecureBootState", "Secure Boot State: ");
    });

    query(L"SELECT * FROM Win32_StartupCommand WHERE Name LIKE '%defender%'", [&](IWbemClassObject* o){
        getProp(o, L"Caption", "WinDef App Policy: ");
        getProp(o, L"Command", "WinDef Command: ");
        getProp(o, L"Location", "WinDef Location: ");
    });

    HKEY h;
    DWORD v, s = sizeof(v);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
       L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &h) == ERROR_SUCCESS) {
        if (RegQueryValueEx(h, L"EnableVirtualizationBasedSecurity", nullptr, nullptr, (LPBYTE)&v, &s) == ERROR_SUCCESS) {
            std::cout << L << "Kernel DMA Protection / VBS enabled: " << V << (v ? "Yes" : "No") << R << "\n";
        }
        RegCloseKey(h);
    }

    svc->Release();
    locator->Release();
    CoUninitialize();
}


bool InitializeCOM() {
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        if (hr == RPC_E_CHANGED_MODE) {
            std::cerr << "COM already initialized with a different concurrency model.\n";
        } else {
            std::cerr << "CoInitializeEx failed. HRESULT = " << std::hex << hr << "\n";
        }
        return false;
    }

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );

    if (FAILED(hr)) {
        std::cerr << "CoInitializeSecurity failed. HRESULT = " << std::hex << hr << "\n";
    }

    return SUCCEEDED(hr);
}


const wchar_t* DecodeVideoArchitecture(int val) {
    switch (val) {
        case 0:  return L"Other";
        case 1:  return L"Unknown";
        case 2:  return L"CGA";
        case 3:  return L"EGA";
        case 4:  return L"VGA";
        case 5:  return L"SVGA";
        case 6:  return L"MDA";
        case 7:  return L"HGC";
        case 8:  return L"MCGA";
        case 9:  return L"PCI";
        case 10: return L"AGP";
        case 11: return L"Memory Mapped I/O";
        case 12: return L"BIOS";
        case 13: return L"ISA";
        case 14: return L"MCA";
        default: return L"(unknown)";
    }
}

std::wstring FormatDriverDate(const std::wstring& wmiDate) {
    if (wmiDate.length() < 8) return L"(invalid date)";
    std::wstring year = wmiDate.substr(0, 4);
    std::wstring month = wmiDate.substr(4, 2);
    std::wstring day = wmiDate.substr(6, 2);
    return year + L"-" + month + L"-" + day;
}

void CmdGPUInfo(const std::string& args) {
    if (!InitializeCOM()) {
        std::cerr << "Failed to initialize COM.\n";
        return;
    }

    IWbemLocator *locator = nullptr;
    IWbemServices *services = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&locator);

    if (FAILED(hr)) {
        std::cerr << "Failed to create IWbemLocator.\n";
        return;
    }

    BSTR namespaceStr = SysAllocString(L"ROOT\\CIMV2");
    hr = locator->ConnectServer(
        namespaceStr,
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &services
    );
    SysFreeString(namespaceStr);

    if (FAILED(hr)) {
        std::cerr << "Failed to connect to WMI.\n";
        locator->Release();
        return;
    }

    BSTR wql = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT Name, DriverVersion, AdapterRAM, VideoProcessor, VideoModeDescription, Status, DriverDate, VideoArchitecture FROM Win32_VideoController");

    IEnumWbemClassObject* enumerator = nullptr;
    hr = services->ExecQuery(
        wql,
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &enumerator
    );

    SysFreeString(wql);
    SysFreeString(query);

    if (FAILED(hr)) {
        std::cerr << "WMI GPU query failed.\n";
        services->Release();
        locator->Release();
        return;
    }

    IWbemClassObject *obj = nullptr;
    ULONG returned = 0;

    while (enumerator) {
        HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &returned);
        if (!returned) break;

        VARIANT name, version, ram;
        VARIANT processor, modeDesc, status, driverDate, videoArch;
        VariantInit(&name);
        VariantInit(&version);
        VariantInit(&ram);
        VariantInit(&processor);
        VariantInit(&modeDesc);
        VariantInit(&status);
        VariantInit(&driverDate);
        VariantInit(&videoArch);

        obj->Get(L"Name", 0, &name, 0, 0);
        obj->Get(L"DriverVersion", 0, &version, 0, 0);
        obj->Get(L"AdapterRAM", 0, &ram, 0, 0);
        obj->Get(L"VideoProcessor", 0, &processor, 0, 0);
        obj->Get(L"VideoModeDescription", 0, &modeDesc, 0, 0);
        obj->Get(L"Status", 0, &status, 0, 0);
        obj->Get(L"DriverDate", 0, &driverDate, 0, 0);
        obj->Get(L"VideoArchitecture", 0, &videoArch, 0, 0);

        ULONGLONG vram = 0;
        if (ram.vt == VT_UI4) {
            vram = ram.ulVal;
        } else if (ram.vt == VT_I8) {
            vram = ram.llVal;
        } else if (ram.vt == VT_UI8) {
            vram = ram.ullVal;
        }

        std::wcout << L"\nGPU Name            : " << (name.vt == VT_BSTR ? name.bstrVal : L"(unknown)") << L"\n"
                   << L"Driver Version      : " << (version.vt == VT_BSTR ? version.bstrVal : L"(unknown)") << L"\n"
                   << L"VRAM (bytes)        : " << vram << L"\n"
                   << L"Video Processor     : " << (processor.vt == VT_BSTR ? processor.bstrVal : L"(unknown)") << L"\n"
                   << L"Video Mode          : " << (modeDesc.vt == VT_BSTR ? modeDesc.bstrVal : L"(unknown)") << L"\n"
                   << L"Status              : " << (status.vt == VT_BSTR ? status.bstrVal : L"(unknown)") << L"\n";

        if (driverDate.vt == VT_BSTR) {
            std::wstring formattedDate = FormatDriverDate(driverDate.bstrVal);
            std::wcout << L"Driver Date         : " << formattedDate << L"\n";
        } else {
            std::wcout << L"Driver Date         : (unknown)\n";
        }

        std::wcout << L"Video Architecture  : "
                   << (videoArch.vt == VT_I4 ? DecodeVideoArchitecture(videoArch.intVal) : L"(unknown)") << L"\n";

        VariantClear(&name);
        VariantClear(&version);
        VariantClear(&ram);
        VariantClear(&processor);
        VariantClear(&modeDesc);
        VariantClear(&status);
        VariantClear(&driverDate);
        VariantClear(&videoArch);
        obj->Release();
    }

    enumerator->Release();
    services->Release();
    locator->Release();
    CoUninitialize();
}

void PrintVariantString(const VARIANT& var, const std::wstring& label) {
    std::wcout << label << L": " << (var.vt == VT_BSTR ? var.bstrVal : L"(unknown)") << L"\n";
}

void CmdBIOSInfo(const std::string& args) {
    if (!InitializeCOM()) {
        std::cerr << ANSI_BOLD_RED "Failed to initialize COM." ANSI_RESET "\n";
        return;
    }

    IWbemLocator* locator = nullptr;
    IWbemServices* services = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&locator);

    if (FAILED(hr)) {
        std::cerr << ANSI_BOLD_RED "Failed to create IWbemLocator." ANSI_RESET "\n";
        CoUninitialize();
        return;
    }

    BSTR namespaceStr = SysAllocString(L"ROOT\\CIMV2");
    hr = locator->ConnectServer(namespaceStr, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
    SysFreeString(namespaceStr);

    if (FAILED(hr)) {
        std::cerr << ANSI_BOLD_RED "Failed to connect to WMI." ANSI_RESET "\n";
        locator->Release();
        CoUninitialize();
        return;
    }

    hr = CoSetProxyBlanket(
        services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    if (FAILED(hr)) {
        std::cerr << ANSI_BOLD_RED "Failed to set proxy blanket." ANSI_RESET "\n";
        services->Release();
        locator->Release();
        CoUninitialize();
        return;
    }

    auto QueryAndPrint = [&](const wchar_t* wqlQuery, const std::vector<std::wstring>& properties, const std::wstring& header) {
        BSTR wql = SysAllocString(L"WQL");
        BSTR query = SysAllocString(wqlQuery);

        IEnumWbemClassObject* enumerator = nullptr;
        hr = services->ExecQuery(wql, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);
        SysFreeString(wql);
        SysFreeString(query);

        if (FAILED(hr)) {
            std::wcerr << L"\x1b[1;31mQuery failed: \x1b[0m" << header << L"\n";
            return;
        }

        IWbemClassObject* obj = nullptr;
        ULONG retCount = 0;
        std::wcout << L"\n" << L"\x1b[1;36m--- " << header << L" ---\x1b[0m" << L"\n";
        while (enumerator && SUCCEEDED(enumerator->Next(WBEM_INFINITE, 1, &obj, &retCount)) && retCount) {
            for (const auto& prop : properties) {
                VARIANT val;
                VariantInit(&val);
                obj->Get(prop.c_str(), 0, &val, nullptr, nullptr);

                std::wcout << L"\x1b[33m" << prop << L":\x1b[0m ";

                if (prop == L"ReleaseDate" && val.vt == VT_BSTR && wcslen(val.bstrVal) >= 8) {
                    std::wstring raw(val.bstrVal);
                    std::wstring dateStr = raw.substr(0,4) + L"-" + raw.substr(4,2) + L"-" + raw.substr(6,2);
                    std::wcout << L"\x1b[92m" << dateStr << L"\x1b[0m\n";
                } else {
                    if (val.vt == VT_BSTR && val.bstrVal)
                        std::wcout << L"\x1b[92m" << val.bstrVal << L"\x1b[0m\n";
                    else
                        std::wcout << L"\x1b[91m(unknown)\x1b[0m\n";
                }

                VariantClear(&val);
            }
            obj->Release();
            std::wcout << L"\n";
        }
        if (enumerator) enumerator->Release();
    };

    QueryAndPrint(
        L"SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber, BIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion FROM Win32_BIOS",
        {L"Manufacturer", L"SMBIOSBIOSVersion", L"ReleaseDate", L"SerialNumber", L"BIOSVersion", L"SMBIOSMajorVersion", L"SMBIOSMinorVersion"},
        L"BIOS Information"
    );

    QueryAndPrint(
        L"SELECT Name, Manufacturer, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor",
        {L"Name", L"Manufacturer", L"MaxClockSpeed", L"NumberOfCores", L"NumberOfLogicalProcessors"},
        L"CPU Information"
    );

    QueryAndPrint(
        L"SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard",
        {L"Manufacturer", L"Product", L"SerialNumber"},
        L"Motherboard Information"
    );

    QueryAndPrint(
        L"SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem",
        {L"Caption", L"Version", L"BuildNumber"},
        L"Operating System Information"
    );

    QueryAndPrint(
        L"SELECT TotalPhysicalMemory FROM Win32_ComputerSystem",
        {L"TotalPhysicalMemory"},
        L"Memory Information"
    );

    QueryAndPrint(
        L"SELECT Name, DriverVersion FROM Win32_VideoController",
        {L"Name", L"DriverVersion"},
        L"GPU Information"
    );

    services->Release();
    locator->Release();
    CoUninitialize();
}


void CmdNetworkAdapters(const std::string& args) {
    if (!InitializeCOM()) {
        std::cerr << "Failed to initialize COM.\n";
        return;
    }

    IWbemLocator* locator = nullptr;
    IWbemServices* services = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&locator);

    if (FAILED(hr)) {
        std::cerr << "Failed to create IWbemLocator.\n";
        return;
    }

    BSTR namespaceStr = SysAllocString(L"ROOT\\CIMV2");
    hr = locator->ConnectServer(
        namespaceStr,
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &services
    );
    SysFreeString(namespaceStr);

    if (FAILED(hr)) {
        std::cerr << "Failed to connect to WMI.\n";
        locator->Release();
        return;
    }

    BSTR wql = SysAllocString(L"WQL");

    std::wstring wArgs;
    if (!args.empty()) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, args.c_str(), (int)args.size(), NULL, 0);
        wArgs.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, args.c_str(), (int)args.size(), &wArgs[0], size_needed);

        size_t pos = 0;
        while ((pos = wArgs.find(L'\'', pos)) != std::wstring::npos) {
            wArgs.replace(pos, 1, L"''");
            pos += 2;
        }
    }

    std::wstring queryStr = L"SELECT Name, Description, MACAddress, Manufacturer, NetConnectionStatus, Speed, AdapterType, DeviceID, PNPDeviceID, ServiceName FROM Win32_NetworkAdapter";
    if (!wArgs.empty()) {
        queryStr += L" WHERE Name = '" + wArgs + L"'";
    }

    BSTR query = SysAllocString(queryStr.c_str());

    IEnumWbemClassObject* enumerator = nullptr;
    hr = services->ExecQuery(
        wql,
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &enumerator
    );

    SysFreeString(wql);
    SysFreeString(query);

    if (FAILED(hr)) {
        std::cerr << "WMI NetworkAdapter query failed.\n";
        services->Release();
        locator->Release();
        return;
    }

    auto printSpeed = [](VARIANT& speed) {
        if (speed.vt == VT_BSTR) {
            try {
                ULONGLONG spd = _wtoi64(speed.bstrVal);
                if (spd > 0 && spd < 1'000'000'000'000ULL)
                    std::wcout << L"Speed            : " << spd / 1000000 << L" Mbps\n";
                else
                    std::wcout << L"Speed            : (invalid)\n";
            } catch (...) {
                std::wcout << L"Speed            : (invalid)\n";
            }
        } else if (speed.vt == VT_UI8) {
            if (speed.ullVal > 0 && speed.ullVal < 1'000'000'000'000ULL)
                std::wcout << L"Speed            : " << speed.ullVal / 1000000 << L" Mbps\n";
            else
                std::wcout << L"Speed            : (invalid)\n";
        } else if (speed.vt == VT_I4) {
            if (speed.intVal > 0 && speed.intVal < 1'000'000'000)
                std::wcout << L"Speed            : " << speed.intVal / 1000000 << L" Mbps\n";
            else
                std::wcout << L"Speed            : (invalid)\n";
        } else {
            std::wcout << L"Speed            : (unknown)\n";
        }
    };

    IWbemClassObject* obj = nullptr;
    ULONG returned = 0;

    bool foundAny = false;

    while (enumerator) {
        HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &returned);
        if (!returned) break;

        foundAny = true;

        VARIANT name, description, mac, manufacturer, status, speed, adapterType, deviceId, pnpId, serviceName;
        VariantInit(&name);
        VariantInit(&description);
        VariantInit(&mac);
        VariantInit(&manufacturer);
        VariantInit(&status);
        VariantInit(&speed);
        VariantInit(&adapterType);
        VariantInit(&deviceId);
        VariantInit(&pnpId);
        VariantInit(&serviceName);

        obj->Get(L"Name", 0, &name, 0, 0);
        obj->Get(L"Description", 0, &description, 0, 0);
        obj->Get(L"MACAddress", 0, &mac, 0, 0);
        obj->Get(L"Manufacturer", 0, &manufacturer, 0, 0);
        obj->Get(L"NetConnectionStatus", 0, &status, 0, 0);
        obj->Get(L"Speed", 0, &speed, 0, 0);
        obj->Get(L"AdapterType", 0, &adapterType, 0, 0);
        obj->Get(L"DeviceID", 0, &deviceId, 0, 0);
        obj->Get(L"PNPDeviceID", 0, &pnpId, 0, 0);
        obj->Get(L"ServiceName", 0, &serviceName, 0, 0);

        std::wcout << L"\n--- Network Adapter ---\n"
                   << L"Name             : " << (name.vt == VT_BSTR ? name.bstrVal : L"(unknown)") << L"\n"
                   << L"Description      : " << (description.vt == VT_BSTR ? description.bstrVal : L"(unknown)") << L"\n"
                   << L"MAC Address      : " << (mac.vt == VT_BSTR ? mac.bstrVal : L"(none)") << L"\n"
                   << L"Manufacturer     : " << (manufacturer.vt == VT_BSTR ? manufacturer.bstrVal : L"(unknown)") << L"\n";

        if (status.vt == VT_I4) {
            switch (status.intVal) {
                case 0: std::wcout << L"Status           : Disconnected\n"; break;
                case 1: std::wcout << L"Status           : Connecting\n"; break;
                case 2: std::wcout << L"Status           : Connected\n"; break;
                case 3: std::wcout << L"Status           : Disconnecting\n"; break;
                case 4: std::wcout << L"Status           : Hardware not present\n"; break;
                case 5: std::wcout << L"Status           : Hardware disabled\n"; break;
                case 6: std::wcout << L"Status           : Hardware malfunction\n"; break;
                case 7: std::wcout << L"Status           : Media disconnected\n"; break;
                case 8: std::wcout << L"Status           : Authenticating\n"; break;
                case 9: std::wcout << L"Status           : Authentication succeeded\n"; break;
                case 10: std::wcout << L"Status          : Authentication failed\n"; break;
                case 11: std::wcout << L"Status          : Invalid Address\n"; break;
                case 12: std::wcout << L"Status          : Credentials Required\n"; break;
                default: std::wcout << L"Status           : Unknown (" << status.intVal << L")\n"; break;
            }
        } else {
            std::wcout << L"Status           : (unknown)\n";
        }

        printSpeed(speed);

        std::wcout << L"Adapter Type     : " << (adapterType.vt == VT_BSTR ? adapterType.bstrVal : L"(unknown)") << L"\n"
                   << L"Device ID        : " << (deviceId.vt == VT_BSTR ? deviceId.bstrVal : L"(unknown)") << L"\n"
                   << L"PNP Device ID    : " << (pnpId.vt == VT_BSTR ? pnpId.bstrVal : L"(unknown)") << L"\n"
                   << L"Service Name     : " << (serviceName.vt == VT_BSTR ? serviceName.bstrVal : L"(unknown)") << L"\n";

        VariantClear(&name);
        VariantClear(&description);
        VariantClear(&mac);
        VariantClear(&manufacturer);
        VariantClear(&status);
        VariantClear(&speed);
        VariantClear(&adapterType);
        VariantClear(&deviceId);
        VariantClear(&pnpId);
        VariantClear(&serviceName);

        obj->Release();
    }

    if (!foundAny && !wArgs.empty()) {
        std::wcerr << L"No network adapter found matching name: " << wArgs << L"\n";
    }

    enumerator->Release();
    services->Release();
    locator->Release();
    CoUninitialize();
}

void CmdBattery(const std::string& args) {
    SYSTEM_POWER_STATUS status;
    if (!GetSystemPowerStatus(&status)) {
        std::cout << "Failed to get battery status." << std::endl;
        return;
    }

    std::cout << "Battery Status:" << std::endl;
    if (status.ACLineStatus == 1)
        std::cout << "  AC Power: Online" << std::endl;
    else if (status.ACLineStatus == 0)
        std::cout << "  AC Power: Offline" << std::endl;
    else
        std::cout << "  AC Power: Unknown" << std::endl;

    if (status.BatteryFlag == 128) {
        std::cout << "  Battery: No system battery detected." << std::endl;
    } else {
        if (status.BatteryLifePercent == 255) {
            std::cout << "  Battery Life Percent: Unknown" << std::endl;
        } else {
            std::cout << "  Battery Life Percent: " << (int)status.BatteryLifePercent << "%" << std::endl;
        }

        if (status.BatteryLifeTime == (DWORD)-1) {
            std::cout << "  Battery Life Time: Unknown" << std::endl;
        } else {
            std::cout << "  Battery Life Time: " << status.BatteryLifeTime << " seconds" << std::endl;
        }
    }
}

void CmdLoadAvg(const std::string& args) {
#ifndef _WIN32
    double loads[3];
    if (getloadavg(loads, 3) == -1) {
        std::cout << "Load average not available.\n";
        return;
    }
    std::cout << "Load Average (1, 5, 15 min): "
              << loads[0] << ", "
              << loads[1] << ", "
              << loads[2] << std::endl;
#else
   std::cout << "Load average is not supported on Windows. Use winloadavg.\n";
#endif
}

void CmdWinLoadAvg(const std::string&) {
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    PDH_FMT_COUNTERVALUE counterVal;

    if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) {
        std::cout << "Failed to open PDH query.\n";
        return;
    }

    if (PdhAddCounter(query, L"\\Processor(_Total)\\% Processor Time", 0, &counter) != ERROR_SUCCESS) {
        std::cout << "Failed to add counter.\n";
        PdhCloseQuery(query);
        return;
    }

    PdhCollectQueryData(query);
    Sleep(1000); 
    PdhCollectQueryData(query);

    if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &counterVal) != ERROR_SUCCESS) {
        std::cout << "Failed to get counter value.\n";
    } else {
        std::cout << "CPU Usage (1s sample): " << counterVal.doubleValue << "%\n";
    }

    PdhCloseQuery(query);
}





void CmdVersion(const std::string&) {
    printf("Zephyr Version 1.0.2\n");
    printf("Update: HTTP Client!\n");
    printf("Built on %s at %s\n", __DATE__, __TIME__);
    printf("Using Windows API: %s\n", _WIN32_WINNT >= 0x0601 ? "Windows 7+" : "Older version");
    printf("Using C++ Standard: %s\n", __cplusplus == 201703L ? "C++17" : "Unknown");
    printf("Compiled with: %s\n", __VERSION__);
    printf("Running on: %s %s\n", GetUsername().c_str(), GetHostname().c_str());
    printf("Current Directory: %s\n", GetCurrentDir().c_str());
    printf("Creator: %s\n", "MuerteSeguraZ");
    
}

void CmdDrywall(const std::string& args) {
    (void)args;
    std::cout << ANSI_BOLD_RED "EASILY FLUSTERED!" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD_RED "IS A BOYKISSER (OMG CUTE?)!" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD_RED "IS A BOTTOM!" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD_RED "LOVES CUDDLES (plus points :3)" << ANSI_RESET << std::endl;
    std::cout << ANSI_BOLD_RED "CLINGY AND AFFECTIONATE (MORE PLUS POINTS!!!!!)" << ANSI_RESET << std::endl;
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
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME, nullptr, nullptr, &bufferSize);
    if (result != ERROR_BUFFER_OVERFLOW) {
        std::cerr << ANSI_RED << "[linkup] Failed to get buffer size for adapters. Error: " << result << ANSI_RESET << std::endl;
        return;
    }

    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* adapterAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapterAddresses, &bufferSize);
    if (result != NO_ERROR) {
        std::cerr << ANSI_RED << "[linkup] Failed to get adapter info. Error: " << result << ANSI_RESET << std::endl;
        return;
    }

    std::cout << ANSI_BOLD_GREEN << "[linkup] Active Network Interfaces:" << ANSI_RESET << "\n";

    for (IP_ADAPTER_ADDRESSES* adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;

        std::string name = adapter->FriendlyName ? WStringToUTF8(adapter->FriendlyName) : "(unknown)";
        std::string desc = adapter->Description ? WStringToUTF8(adapter->Description) : "(unknown)";
        std::string dnsSuffix = adapter->DnsSuffix ? WStringToUTF8(adapter->DnsSuffix) : "";

        std::string ifType;
        switch (adapter->IfType) {
            case IF_TYPE_ETHERNET_CSMACD: ifType = "Ethernet"; break;
            case IF_TYPE_IEEE80211:       ifType = "Wi-Fi"; break;
            case MIB_IF_TYPE_LOOPBACK:    ifType = "Loopback"; break; 
            case IF_TYPE_TUNNEL:          ifType = "Tunnel"; break;
            case IF_TYPE_PPP:             ifType = "PPP"; break;
            case IF_TYPE_SLIP:            ifType = "SLIP"; break;
            default:                     ifType = "Other"; break;
        }

        std::cout << ANSI_YELLOW << "============================================================" << ANSI_RESET << "\n";
        std::cout << ANSI_BOLD_GREEN << "↪ Interface Name:      " << ANSI_RESET << name << "\n";
        std::cout << ANSI_BOLD_GREEN << "  Network Name:        " << ANSI_RESET << desc << "\n";
        std::cout << ANSI_BOLD_GREEN << "  DNS Suffix:          " << ANSI_RESET << (dnsSuffix.empty() ? "(none)" : dnsSuffix) << "\n";
        std::cout << ANSI_BOLD_GREEN << "  Interface Type:      " << ANSI_RESET << ifType << "\n";

        std::cout << ANSI_BOLD_GREEN << "  MAC:                 " << ANSI_RESET;
        if (adapter->PhysicalAddressLength == 0) {
            std::cout << "(none)\n";
        } else {
            for (UINT i = 0; i < adapter->PhysicalAddressLength; ++i) {
                printf("%02X", adapter->PhysicalAddress[i]);
                if (i != adapter->PhysicalAddressLength - 1) printf("-");
            }
            std::cout << "\n";
        }

        // MTU
        std::cout << ANSI_BOLD_GREEN << "  MTU:                 " << ANSI_RESET << adapter->Mtu << "\n";

        // Speed (convert to Mbps, if speed is non-zero)
        if (adapter->TransmitLinkSpeed != 0) {
            // Speed is in bits per second, so divide by 1,000,000 to get Mbps
            uint64_t speedMbps = adapter->TransmitLinkSpeed / 1000000;
            std::cout << ANSI_BOLD_GREEN << "  Link Speed:          " << ANSI_RESET << speedMbps << " Mbps\n";
        } else {
            std::cout << ANSI_BOLD_GREEN << "  Link Speed:          " << ANSI_RESET << "(unknown)\n";
        }

        std::cout << ANSI_BOLD_GREEN << "  OperStatus:          " << ANSI_RESET
                  << (adapter->OperStatus == IfOperStatusUp ? "Up" : "Down") << "\n";
        std::cout << ANSI_BOLD_GREEN << "  Is Receive Only:     " << ANSI_RESET
                  << (adapter->ReceiveOnly ? "Yes" : "No") << "\n";
        std::cout << ANSI_BOLD_GREEN << "  Is Point To Point:   " << ANSI_RESET
                  << (adapter->IfType == IF_TYPE_PPP ? "Yes" : "No") << "\n";
        std::cout << ANSI_BOLD_GREEN << "  Supports Multicast:  " << ANSI_RESET
                  << ((adapter->Flags & IP_ADAPTER_NO_MULTICAST) ? "No" : "Yes") << "\n";

        // Loopback confirmation
        std::cout << ANSI_BOLD_GREEN << "  Is Loopback:         " << ANSI_RESET
                  << ((adapter->IfType == MIB_IF_TYPE_LOOPBACK) ? "Yes" : "No") << "\n";

        bool hasIP = false;
        for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
            if (!ua->Address.lpSockaddr) continue;

            char ipStr[INET6_ADDRSTRLEN] = {0};
            void* addrPtr = nullptr;
            bool isIPv4 = false;

            if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                addrPtr = &(ipv4->sin_addr);
                isIPv4 = true;
            } else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                addrPtr = &(ipv6->sin6_addr);
            }

            if (addrPtr && inet_ntop(ua->Address.lpSockaddr->sa_family, addrPtr, ipStr, sizeof(ipStr))) {
                hasIP = true;
                if (isIPv4) {
                    std::cout << ANSI_BOLD_GREEN << "  IP Address:         " << ANSI_RESET << ipStr << "\n";

                    uint8_t prefix = ua->OnLinkPrefixLength;
                    if (prefix <= 32) {
                        uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
                        in_addr maskAddr;
                        maskAddr.s_addr = htonl(mask);
                        char maskStr[INET_ADDRSTRLEN] = {};
                        inet_ntop(AF_INET, &maskAddr, maskStr, sizeof(maskStr));
                        std::cout << ANSI_BOLD_GREEN << "  Subnet Mask:        " << ANSI_RESET << maskStr << "\n";
                    }
                } else {
                    std::cout << ANSI_BOLD_GREEN << "  IP Address:         " << ANSI_RESET << ipStr << "\n";
                    std::cout << ANSI_BOLD_GREEN << "  Subnet Prefix:      " << ANSI_RESET << "/" << static_cast<int>(ua->OnLinkPrefixLength) << "\n";
                }
            }
        }

        if (!hasIP) {
            std::cout << ANSI_BOLD_GREEN << "  IP Address:         " << ANSI_RESET << "(none assigned)\n";
        }

        std::cout << ANSI_BOLD_GREEN << "  DHCPv4:             " << ANSI_RESET
                  << ((adapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "Enabled" : "Disabled") << "\n";

        if (adapter->Dhcpv4Server.lpSockaddr) {
            char dhcpServerStr[INET_ADDRSTRLEN] = {};
            if (adapter->Dhcpv4Server.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* dhcpv4 = reinterpret_cast<sockaddr_in*>(adapter->Dhcpv4Server.lpSockaddr);
                inet_ntop(AF_INET, &(dhcpv4->sin_addr), dhcpServerStr, sizeof(dhcpServerStr));
                std::cout << ANSI_BOLD_GREEN << "  DHCPv4 Server:      " << ANSI_RESET << dhcpServerStr << "\n";
            }
        }

        bool dhcpv6_enabled = false;
#ifdef IP_ADAPTER_DHCPV6_ENABLED
        dhcpv6_enabled = (adapter->Flags & IP_ADAPTER_DHCPV6_ENABLED) != 0;
#endif
        std::cout << ANSI_BOLD_GREEN << "  DHCPv6:             " << ANSI_RESET
                  << (dhcpv6_enabled ? "Enabled" : "Disabled") << "\n";

        if (adapter->Dhcpv6Server.lpSockaddr) {
            char dhcpv6ServerStr[INET6_ADDRSTRLEN] = {};
            if (adapter->Dhcpv6Server.lpSockaddr->sa_family == AF_INET6) {
                sockaddr_in6* dhcpv6 = reinterpret_cast<sockaddr_in6*>(adapter->Dhcpv6Server.lpSockaddr);
                if (inet_ntop(AF_INET6, &(dhcpv6->sin6_addr), dhcpv6ServerStr, sizeof(dhcpv6ServerStr))) {
                    std::cout << ANSI_BOLD_GREEN << "  DHCPv6 Server:      " << ANSI_RESET << dhcpv6ServerStr << "\n";
                }
            }
        }

        if (adapter->FirstGatewayAddress) {
            for (IP_ADAPTER_GATEWAY_ADDRESS* gw = adapter->FirstGatewayAddress; gw != nullptr; gw = gw->Next) {
                if (gw->Address.lpSockaddr) {
                    char gwStr[INET6_ADDRSTRLEN] = {};
                    if (gw->Address.lpSockaddr->sa_family == AF_INET) {
                        sockaddr_in* gw4 = reinterpret_cast<sockaddr_in*>(gw->Address.lpSockaddr);
                        inet_ntop(AF_INET, &(gw4->sin_addr), gwStr, sizeof(gwStr));
                    } else if (gw->Address.lpSockaddr->sa_family == AF_INET6) {
                        sockaddr_in6* gw6 = reinterpret_cast<sockaddr_in6*>(gw->Address.lpSockaddr);
                        inet_ntop(AF_INET6, &(gw6->sin6_addr), gwStr, sizeof(gwStr));
                    }
                    std::cout << ANSI_BOLD_GREEN << "  Gateway:            " << ANSI_RESET << gwStr << "\n";
                }
            }
        }

        if (adapter->FirstDnsServerAddress) {
            std::cout << ANSI_BOLD_GREEN << "  DNS Servers:        " << ANSI_RESET;
            IP_ADAPTER_DNS_SERVER_ADDRESS* dns = adapter->FirstDnsServerAddress;
            bool firstDns = true;
            for (; dns != nullptr; dns = dns->Next) {
                if (dns->Address.lpSockaddr) {
                    char dnsStr[INET6_ADDRSTRLEN] = {};
                    if (dns->Address.lpSockaddr->sa_family == AF_INET) {
                        sockaddr_in* dns4 = reinterpret_cast<sockaddr_in*>(dns->Address.lpSockaddr);
                        inet_ntop(AF_INET, &(dns4->sin_addr), dnsStr, sizeof(dnsStr));
                    } else if (dns->Address.lpSockaddr->sa_family == AF_INET6) {
                        sockaddr_in6* dns6 = reinterpret_cast<sockaddr_in6*>(dns->Address.lpSockaddr);
                        inet_ntop(AF_INET6, &(dns6->sin6_addr), dnsStr, sizeof(dnsStr));
                    }
                    if (!firstDns) std::cout << ", ";
                    std::cout << dnsStr;
                    firstDns = false;
                }
            }
            std::cout << "\n";
        }

        std::cout << "\n";
    }

    std::cout << ANSI_YELLOW << "============================================================" << ANSI_RESET << "\n";
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

    // Get drive type
    UINT driveType = GetDriveTypeA((driveLetter + "\\").c_str());
    std::string driveTypeStr;
    switch (driveType) {
        case DRIVE_UNKNOWN: driveTypeStr = "Unknown"; break;
        case DRIVE_NO_ROOT_DIR: driveTypeStr = "Invalid Root Path"; break;
        case DRIVE_REMOVABLE: driveTypeStr = "Removable"; break;
        case DRIVE_FIXED: driveTypeStr = "Fixed"; break;
        case DRIVE_REMOTE: driveTypeStr = "Network"; break;
        case DRIVE_CDROM: driveTypeStr = "CD-ROM"; break;
        case DRIVE_RAMDISK: driveTypeStr = "RAM Disk"; break;
        default: driveTypeStr = "Other"; break;
    }

    // Get disk space info
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    BOOL spaceSuccess = GetDiskFreeSpaceExA(
        (driveLetter + "\\").c_str(),
        &freeBytesAvailable,
        &totalNumberOfBytes,
        &totalNumberOfFreeBytes
    );

    auto formatBytes = [](ULARGE_INTEGER bytes) -> std::string {
        double size = static_cast<double>(bytes.QuadPart);
        const char* units[] = { "B", "KB", "MB", "GB", "TB" };
        int unitIndex = 0;
        while (size >= 1024.0 && unitIndex < 4) {
            size /= 1024.0;
            ++unitIndex;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "%.2f %s", size, units[unitIndex]);
        return std::string(buf);
    };

    std::cout << "[diskinfo] Drive: " << driveLetter << "\n";
    std::cout << "  Drive Type: " << driveTypeStr << "\n";
    std::cout << "  Volume Label: " << (strlen(volumeName) ? volumeName : "(none)") << "\n";
    std::cout << "  Serial Number: " << std::hex << std::uppercase
              << ((serialNumber >> 16) & 0xFFFF) << "-"
              << (serialNumber & 0xFFFF) << std::dec << "\n";
    std::cout << "  File System: " << fileSystemName << "\n";

    if (spaceSuccess) {
        std::cout << "  Total Size: " << formatBytes(totalNumberOfBytes) << "\n";
        std::cout << "  Free Space: " << formatBytes(totalNumberOfFreeBytes) << "\n";
    } else {
        std::cout << "  Failed to get disk space info.\n";
    }

    // Optional: Decode some file system flags
    std::cout << "  File System Flags: ";
    if (fileSystemFlags & FILE_READ_ONLY_VOLUME) std::cout << "ReadOnly ";
    if (fileSystemFlags & FILE_SUPPORTS_ENCRYPTION) std::cout << "Encryption ";
    if (fileSystemFlags & FILE_SUPPORTS_COMPRESSION) std::cout << "Compression ";
    if (fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES) std::cout << "SparseFiles ";
    if (fileSystemFlags & FILE_SUPPORTS_REPARSE_POINTS) std::cout << "ReparsePoints ";
    if (fileSystemFlags & FILE_SUPPORTS_REMOTE_STORAGE) std::cout << "RemoteStorage ";
    std::cout << "\n";
}

void PrintRegistryStartupApps(HKEY rootKey, const std::string& subKey, const std::string& scope) {
    HKEY hKey;
    if (RegOpenKeyExA(rootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    char name[256], value[1024];
    DWORD nameLen, valueLen, type;
    DWORD index = 0;

    std::cout << "\033[1;36m[" << scope << " Registry: " << subKey << "]\033[0m\n";
    while (true) {
        nameLen = sizeof(name);
        valueLen = sizeof(value);
        if (RegEnumValueA(hKey, index++, name, &nameLen, nullptr, &type, (LPBYTE)value, &valueLen) != ERROR_SUCCESS)
            break;

        if (type == REG_SZ) {
            std::cout << "  \033[1;33m" << name << "\033[0m => " << value << "\n";
        }
    }

    RegCloseKey(hKey);
}

void PrintStartupFolderApps(const std::string& path, const std::string& scope) {
    std::cout << "\033[1;36m[" << scope << " Startup Folder]\033[0m\n";
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        std::cout << "  \033[1;33m" << entry.path().filename().string() << "\033[0m\n";
    }
}

void CmdStartupApps(const std::string&) {
    PrintRegistryStartupApps(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Current User");
    PrintRegistryStartupApps(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "All Users");

    char path[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
        PrintStartupFolderApps(path, "Current User");
    }

    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, path))) {
        PrintStartupFolderApps(path, "All Users");
    }
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

    std::string titleToSet = args;
    if (args == "reset") {
        titleToSet = "Zephyr";
    }

    if (SetConsoleTitleA(titleToSet.c_str())) {
        std::cout << "[CTITLE] Title set to: " << titleToSet << "\n";
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

bool EndProcessByName(const std::string& nameToKill) {
    std::wstring wname = WCharToWString(std::wstring(nameToKill.begin(), nameToKill.end()).c_str());

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    bool success = false;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wname.c_str()) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    success = TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                }
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return success;
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

void CmdTar(const std::string& args) {
    std::istringstream iss(args);
    std::string archiveName;
    iss >> archiveName;

    if (archiveName.empty()) {
        std::cout << "Usage: tar <archive.tar> <file1> [file2 ...]" << std::endl;
        return;
    }

    std::ofstream archive(archiveName, std::ios::binary);
    if (!archive.is_open()) {
        std::cout << "Failed to create archive: " << archiveName << std::endl;
        return;
    }

    std::string file;
    while (iss >> file) {
        std::ifstream infile(file, std::ios::binary);
        if (!infile.is_open()) {
            std::cout << "Cannot open file: " << file << std::endl;
            continue;
        }

        infile.seekg(0, std::ios::end);
        std::streamsize size = infile.tellg();
        infile.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        infile.read(buffer.data(), size);

        uint32_t nameLen = static_cast<uint32_t>(file.size());
        uint64_t dataLen = static_cast<uint64_t>(size);

        archive.write(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        archive.write(file.c_str(), nameLen);
        archive.write(reinterpret_cast<char*>(&dataLen), sizeof(dataLen));
        archive.write(buffer.data(), size);
    }

    archive.close();
    std::cout << "Archive " << archiveName << " created successfully." << std::endl;
}

void CmdGrep(const std::string& args) {
    std::istringstream iss(args);
    std::string token;

    bool flag_i = false;
    bool flag_v = false; 
    bool flag_n = false; 
    bool flag_c = false; 

    while (iss >> token && !token.empty() && token[0] == '-') {
        for (size_t i = 1; i < token.size(); ++i) {
            switch (token[i]) {
                case 'i': flag_i = true; break;
                case 'v': flag_v = true; break;
                case 'n': flag_n = true; break;
                case 'c': flag_c = true; break;
                default:
                    std::cout << "Unknown flag -" << token[i] << std::endl;
                    return;
            }
        }
    }

    std::string pattern = token;
    std::string filename;
    iss >> filename;

    if (pattern.empty() || filename.empty()) {
        std::cout << "Usage: grep [-i] [-v] [-n] [-c] <pattern> <file>" << std::endl;
        return;
    }

    std::string pattern_cmp = pattern;
    if (flag_i) {
        std::transform(pattern_cmp.begin(), pattern_cmp.end(), pattern_cmp.begin(),
            [](unsigned char c){ return std::tolower(c); });
    }

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "Cannot open file: " << filename << std::endl;
        return;
    }

    std::string line;
    int lineNumber = 1;
    int matchCount = 0;

    while (std::getline(file, line)) {
        std::string line_cmp = line;
        if (flag_i) {
            std::transform(line_cmp.begin(), line_cmp.end(), line_cmp.begin(),
                [](unsigned char c){ return std::tolower(c); });
        }

        bool found = (line_cmp.find(pattern_cmp) != std::string::npos);
        if (flag_v) found = !found;

        if (found) {
            ++matchCount;
            if (!flag_c) {
                if (flag_n) {
                    std::cout << lineNumber << ": ";
                }
                std::cout << line << std::endl;
            }
        }

        ++lineNumber;
    }

    if (flag_c) {
        std::cout << matchCount << std::endl;
    } else if (matchCount == 0) {
        std::cout << "No matches found for pattern \"" << pattern << "\" in file " << filename << "." << std::endl;
    }
}

void CmdSed(const std::string& args) {
    std::istringstream iss(args);
    std::string cmd, filename;
    iss >> cmd >> filename;

    if (cmd.empty() || filename.empty()) {
        std::cout << "Usage: sed s/old/new/[flags] <filename>" << std::endl;
        return;
    }

    if (cmd.size() < 5 || cmd[0] != 's') {
        std::cout << "Error: Only simple substitution supported, use syntax: s/old/new/[flags]" << std::endl;
        return;
    }

    char delim = cmd[1];
    size_t secondDelim = cmd.find(delim, 2);
    if (secondDelim == std::string::npos) {
        std::cout << "Error: Invalid sed command syntax." << std::endl;
        return;
    }
    size_t thirdDelim = cmd.find(delim, secondDelim + 1);
    if (thirdDelim == std::string::npos) {
        std::cout << "Error: Invalid sed command syntax." << std::endl;
        return;
    }

    std::string oldStr = cmd.substr(2, secondDelim - 2);
    std::string newStr = cmd.substr(secondDelim + 1, thirdDelim - secondDelim - 1);

    std::string flags = cmd.substr(thirdDelim + 1);

    bool caseInsensitive = false;
    bool globalReplace = true;

    for (char f : flags) {
        if (f == 'i') caseInsensitive = true;
        else if (f == 'g') globalReplace = true;
        else {
            std::cout << "Error: Unsupported flag '" << f << "'." << std::endl;
            return;
        }
    }

    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        std::cout << "Cannot open file: " << filename << std::endl;
        return;
    }

    std::string tempFilename = filename + ".sedtmp";
    std::ofstream outFile(tempFilename);
    if (!outFile.is_open()) {
        std::cout << "Cannot create temporary output file." << std::endl;
        return;
    }

    auto find_ci = [](const std::string& haystack, const std::string& needle, size_t pos = 0) -> size_t {
        auto it = std::search(
            haystack.begin() + pos, haystack.end(),
            needle.begin(), needle.end(),
            [](char a, char b) {
                return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
            });
        return (it == haystack.end()) ? std::string::npos : (size_t)(it - haystack.begin());
    };

    std::string line;
    while (std::getline(inFile, line)) {
        size_t pos = 0;
        while (true) {
            size_t foundPos = caseInsensitive ? find_ci(line, oldStr, pos) : line.find(oldStr, pos);
            if (foundPos == std::string::npos)
                break;

            line.replace(foundPos, oldStr.length(), newStr);

            if (!globalReplace)
                break;

            pos = foundPos + newStr.length();
        }
        outFile << line << "\n";
    }

    inFile.close();
    outFile.close();

    if (std::remove(filename.c_str()) != 0) {
        std::cout << "Error deleting original file." << std::endl;
        return;
    }
    if (std::rename(tempFilename.c_str(), filename.c_str()) != 0) {
        std::cout << "Error renaming temp file." << std::endl;
        return;
    }

    std::cout << "Substitution complete: replaced \"" << oldStr << "\" with \"" << newStr << "\" in " << filename;
    if (flags.size() > 0) std::cout << " with flags '" << flags << "'";
    std::cout << std::endl;
}

void CmdBasename(const std::string& args) {
    std::istringstream iss(args);
    std::string path;
    iss >> path;

    if (path.empty()) {
        std::cout << "Usage: basename <path>" << std::endl;
        return;
    }

    try {
        std::filesystem::path p(path);
        std::cout << p.filename().string() << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Error getting basename: " << e.what() << std::endl;
    }
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

void CmdHead(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    int lines = 10;

    iss >> filename;
    if (!(iss >> lines)) {
        lines = 10;
    }
    std::ifstream file(filename);
    if (filename.empty()) {
        std::cout << "Usage: head <file> [lines]" << std::endl;
        return;
    }

    std::string line;
    int count = 0;
    while (count < lines && std::getline(file, line)) {
        std::cout << line << std::endl;
        ++count; 
    }
 }

void CmdTail(const std::string& args) {
    std::istringstream iss(args);
    std::string filename;
    int lines = 10;

    iss >> filename;
    if (!(iss >> lines)) {
        lines = 10;
    }

    if (filename.empty()) {
        std::cout << "Usage: tail <file> [lines]" << std::endl;
        return;
    }

    std::ifstream file(filename);
    if (!file) {
        std::cout << "Cannot open file: " << filename << std::endl;
        return;
    }

    std::deque<std::string> buffer;
    std::string line;

    while (std::getline(file, line)) {
        buffer.push_back(line);
        if ((int)buffer.size() > lines) {
            buffer.pop_front();
        }
    }

    for (const auto& l : buffer) {
        std::cout << l << std::endl;
    }
}
 
bool contains_case_insensitive(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    std::string hay = haystack, need = needle;
    std::transform(hay.begin(), hay.end(), hay.begin(), ::tolower);
    std::transform(need.begin(), need.end(), need.begin(), ::tolower);
    return hay.find(need) != std::string::npos;
}

void CmdDnsFlush(const std::string&) {
    system("ipconfig /flushdns");
    std::cout << "DNS cache flushed.\n";
}

void CmdGroups(const std::string& args) {
    (void)args; 

    WCHAR username[256];
    DWORD size = 256;
    if (!GetUserNameW(username, &size)) {
        std::cerr << "Failed to get username.\n";
        return;
    }

    LPLOCALGROUP_USERS_INFO_0 pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;

    if (NetUserGetLocalGroups(nullptr, username, 0, LG_INCLUDE_INDIRECT,
                              (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries) == NERR_Success) {
        std::wcout << L"Groups for " << username << L":\n";
        for (DWORD i = 0; i < entriesRead; ++i) {
            std::wcout << L" - " << pBuf[i].lgrui0_name << L"\n";
        }
        NetApiBufferFree(pBuf);
    } else {
        std::cerr << "Failed to get group information.\n";
    }
}

void CmdClipCopy(const std::string& args) {
    if (args.empty()) {
        std::cerr << "Usage: clipcopy <file> or clipcopy \"text\"\n";
        return;
    }

    std::string textToCopy;

    std::ifstream file(args, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        std::ostringstream ss;
        ss << file.rdbuf();
        textToCopy = ss.str();
        file.close();
    } else {
        textToCopy = args;

        if (!textToCopy.empty() && textToCopy.front() == '"' && textToCopy.back() == '"') {
            textToCopy = textToCopy.substr(1, textToCopy.size() - 2);
        }
    }

    if (textToCopy.empty()) {
        std::cerr << "Nothing to copy.\n";
        return;
    }

    int wideLen = MultiByteToWideChar(CP_UTF8, 0, textToCopy.c_str(), -1, nullptr, 0);
    if (wideLen <= 0) {
        std::cerr << "Failed to convert text to wide string.\n";
        return;
    }

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, wideLen * sizeof(wchar_t));
    if (!hMem) {
        std::cerr << "Failed to allocate global memory.\n";
        return;
    }

    wchar_t* pMem = static_cast<wchar_t*>(GlobalLock(hMem));
    if (!pMem) {
        std::cerr << "Failed to lock global memory.\n";
        GlobalFree(hMem);
        return;
    }

    MultiByteToWideChar(CP_UTF8, 0, textToCopy.c_str(), -1, pMem, wideLen);
    GlobalUnlock(hMem);

    bool opened = false;
    for (int i = 0; i < 5; ++i) {
        if (OpenClipboard(nullptr)) {
            opened = true;
            break;
        }
        Sleep(100);
    }

    if (!opened) {
        std::cerr << "Failed to open clipboard after multiple attempts.\n";
        GlobalFree(hMem);
        return;
    }

    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
        std::cerr << "Failed to set clipboard data.\n";
        GlobalFree(hMem);
        CloseClipboard();
        return;
    }

    CloseClipboard();
    std::cout << "Copied to clipboard.\n";
}


bool RunBatchIfExists(const std::string& command, const std::string& args) {
    namespace fs = std::filesystem;

    std::string batFilename = command + ".bat";

    if (fs::exists(batFilename)) {
        std::string fullCmd = "cmd.exe /c \"" + batFilename + "\"";
        if (!args.empty()) {
            fullCmd += " " + args;
        }
        std::system(fullCmd.c_str());
        return true;  
    } else {
        return false; 
    }
}

void CmdHelp(const std::string&) {
    std::cout <<
    "ZEPHYR COMMAND HELP\n"    
    "====================================================================================================\n"
    "| Commands:                                                                                        |\n"
    "| list [dir]          - List directory contents                                                    |\n"
    "| tree                - Show all files in a specified directory (by path)                          |\n"
    "| hop [dir/noargs/~userhome] - Takes you to a specified directory. If not, says current says info. |\n"
    "| send <src> <dst>    - Copy file                                                                  |\n"
    "| zap <file>          - Delete file                                                                |\n"
    "| fzap <file>         - Securely wipe and delete a file with multiple overwrite passes             |\n"
    "| shift <src> <dst>   - Move/rename file                                                           |\n"
    "| mkplace <dir>       - Create directory                                                           |\n"
    "| clear               - Clear screen                                                               |\n"
    "| bye                 - Exit shell                                                                 |\n"
    "| look                - Show directory tree                                                        |\n"
    "| read <file>         - Display file contents                                                      |\n"
    "| peek <file>         - Display first few lines of a specified file.                               |\n"
    "| head <file> [lines] - Show the first n lines of a file (default is 10)                           |\n"
    "| tail <file> [lines] - Show the last n lines of a file (default is 10)                            |\n"
    "| wc <file> [flags] — Count lines (-l), words (-w), and bytes (-c) in a file.                      |\n"
    "| write <file> <text> - Append text to file                                                        |\n"
    "| run <program>       - Run program                                                                |\n"
    "| echoe <text>        - Echo text                                                                  |\n"
    "| whereami            - Show current directory                                                     |\n"
    "| sysinfo             - Show system info                                                           |\n"
    "| battery             - Show battery info (laptop only)                                            |\n"
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
    "| gpuinfo             - Show GPU info                                                              |\n"
    "| raminfo             - Show detailed RAM, page file, and virtual memory stats                     |\n"
    "| biosinfo            - Show BIOS info                                                             |\n"
    "| userinfo            - Basic details about the current user’s identity and its permissions.       |\n"
    "| whoami [-ext]       - Show current user info, with extended details if -ext is used.             |\n"
    "| uptime              - Show system uptime                                                         |\n"
    "| netstat             - Show network connections and listening ports                               |\n"
    "| ntwkadp             - Shows adapters and their info. Show single info by name (ntwkadp (name))   |\n"
    "| mirror <source> <destination> - Mirror a directory structure                                     |\n"
    "| killtree <pid>      - Terminate a process tree by PID                                            |\n"
    "| pingtest <host>     - Ping a host and display results continuously                               |\n"
    "| scan <host>         - Scan for open ports on a host                                              |\n"
    "| stat <filename>     - Prints statistics of a given file                                          |\n"
    "| cutemessage         - This is for my gf guys please don't run it                                 |\n"
    "| checkadmin          - Check if the process is running as admin                                   |\n"
    "| dnsflush            - Flush DNS resolver cache                                                   |\n"
    "| firewall            - Show Windows firewall status                                               |\n"
    "| drives              - List all available logical drives                                          |\n"
    "| lsusb               - List all available USB's                                                   |\n"
    "| smart               - Display SMART status of disk drives                                        |\n"
    "| gzip <file>         - Compress a file using zlib (produces .gz)                                  |\n"
    "| gunzip <file.gz>    - Decompress a .gz file using zlib                                           |\n"
    "| zip <src> <dst.zip> - Create a zip archive using PowerShell                                      |\n"
    "| unzip <zip> [dir]   - Extract a zip archive using PowerShell                                     |\n"
    "| basename            - Show filename from path                                                    |\n"
    "| loadavg             - Show current CPU usage (sampled over 1 second)                             |\n"
    "| winloadavg          - Same as loadavg, but for Windows.                                          |\n"
    "| mounts              - Displays a list of logical drives and their mount points or volumes.       |\n"
    "| startupapps         - Displays a list of startup apps.                                           |\n"
    "| fmeta               - Display detailed metadata and hash of a file                               |\n"
    "| fhash <file>        - Calculate and display the hash of a file (MD5, SHA1, SHA256)               |\n"
    "| fsize <bytes>       - Convert bytes to human-readable format (KB, MB, GB, TB)                    |\n"
    "| groups              - Show groups the current user belongs to                                    |\n"
    "| hexdump <file>      - Display file contents in hex format                                        |\n"
    "| jobs                - Show all running jobs in the shell                                         |\n"
    "| startjob <command>  - Start a new job in the background and display its ID.                      |\n"
    "| stopjob <job_id>    - Stop a running job by its ID.                                              |\n"
    "| bgjob               - Move a job to the background by ID                                         |\n"
    "| fgjob               - Move a job to the foreground by ID                                         |\n"
    "| clipcopy <file|text>- Copy file contents or raw text to the clipboard                            |\n"
    "| inspect             - Run this to get the inspect help command.                                  |\n"     
    "| http                - Run this to get the HTTP Client help command.                              |\n"                            
    "| You can also run .bat, .exe, .ps1, .py, .js, .cpp and .vbs files.                                |\n"
    "========================================================================================================================\n"
    "| grep - grep searches for patterns in files; flags modify behavior like case (-i), invert (-v), line numbers (-n), and recursion (-r).\n"
    "| sed s/old/new/[flags] <file> - sed replaces text in a file; flags control scope and case sensitivity.\n"
    "========================================================================================================================\n";
}   
