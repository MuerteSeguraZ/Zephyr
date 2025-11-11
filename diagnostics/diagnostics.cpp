#include <windows.h>
#include <psapi.h>
#include <setupapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <comdef.h>
#include <taskschd.h>
#include <Wbemidl.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

bool HasFlag(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}

TASK_STATE StringToTaskState(const std::string& mode) {
    if (mode == "unknown") return TASK_STATE_UNKNOWN;
    if (mode == "disabled") return TASK_STATE_DISABLED;
    if (mode == "queued") return TASK_STATE_QUEUED;
    if (mode == "ready") return TASK_STATE_READY;
    if (mode == "running") return TASK_STATE_RUNNING;
    if (mode == "suspended") return TASK_STATE_DISABLED; // Task Scheduler does not have suspended, you can filter manually
    return TASK_STATE_UNKNOWN;
}

std::string GetArgValue(const std::vector<std::string>& args, const std::string& prefix) {
    for (const auto& arg : args) {
        if (arg.rfind(prefix, 0) == 0) {
            return arg.substr(prefix.length());
        }
    }
    return "";
}

std::wstring NormalizeDriverPath(const std::wstring& path) {
    if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t windowsDir[MAX_PATH];
        GetWindowsDirectoryW(windowsDir, MAX_PATH);
        std::wstring resolved = windowsDir;
        resolved += path.substr(11); // skip "\SystemRoot"
        return resolved;
    }
    return path;
}

// Normalize date string by removing '/' and '-' to compare as plain digits (YYYYMMDD)
bool DateGreaterOrEqual(const std::wstring& wdate, const std::wstring& wthreshold) {
    std::wstring date = wdate;
    std::wstring threshold = wthreshold;

    date.erase(std::remove(date.begin(), date.end(), L'/'), date.end());
    date.erase(std::remove(date.begin(), date.end(), L'-'), date.end());

    threshold.erase(std::remove(threshold.begin(), threshold.end(), L'/'), threshold.end());
    threshold.erase(std::remove(threshold.begin(), threshold.end(), L'-'), threshold.end());

    return date >= threshold;
}

void CmdDiagnosticsIntegrity(const std::string& cmdline) {
    std::vector<std::string> args;
    std::istringstream ss(cmdline);
    for (std::string arg; ss >> arg;) args.push_back(arg);

    const bool asJson = HasFlag(args, "--json");
    const bool countOnly = HasFlag(args, "--count");
    const std::string filterId = GetArgValue(args, "--hotfixid=");
    const std::string afterDate = GetArgValue(args, "--after="); // Format: YYYY-MM-DD
    const std::wstring afterDateW(afterDate.begin(), afterDate.end());

    int count = 0;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m COM init failed.\n";
        return;
    }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m COM security init failed.\n";
        CoUninitialize();
        return;
    }

    IWbemLocator* pLocator = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m WbemLocator create failed.\n";
        CoUninitialize();
        return;
    }

    IWbemServices* pServices = nullptr;
    hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, nullptr, &pServices);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m WMI connect failed.\n";
        pLocator->Release();
        CoUninitialize();
        return;
    }

    hr = CoSetProxyBlanket(pServices,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);

    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m CoSetProxyBlanket failed.\n";
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pServices->ExecQuery(
        bstr_t(L"WQL"),
        bstr_t(L"SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m WMI query failed.\n";
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return;
    }

    if (!asJson && !countOnly)
        std::cout << "\033[36m[Diagnostics]\033[0m Installed Windows Hotfixes:\n";

    if (asJson) std::cout << "[\n";

    IWbemClassObject* pClassObject = nullptr;
    ULONG uReturn = 0;
    bool firstJson = true;

    while (pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn) == S_OK) {
        VARIANT vtHotFixID, vtDate, vtDesc;
        VariantInit(&vtHotFixID); VariantInit(&vtDate); VariantInit(&vtDesc);

        pClassObject->Get(L"HotFixID", 0, &vtHotFixID, 0, 0);
        pClassObject->Get(L"InstalledOn", 0, &vtDate, 0, 0);
        pClassObject->Get(L"Description", 0, &vtDesc, 0, 0);

        std::wstring id = vtHotFixID.vt == VT_BSTR && vtHotFixID.bstrVal ? vtHotFixID.bstrVal : L"";
        std::wstring date = vtDate.vt == VT_BSTR && vtDate.bstrVal ? vtDate.bstrVal : L"";
        std::wstring desc = vtDesc.vt == VT_BSTR && vtDesc.bstrVal ? vtDesc.bstrVal : L"";

        bool matchesId = filterId.empty() || (id.find(std::wstring(filterId.begin(), filterId.end())) != std::wstring::npos);
        bool matchesDate = afterDate.empty() || DateGreaterOrEqual(date, afterDateW);

        if (matchesId && matchesDate) {
            count++;
            if (countOnly) {
                VariantClear(&vtHotFixID);
                VariantClear(&vtDate);
                VariantClear(&vtDesc);
                pClassObject->Release();
                continue;
            }

            if (asJson) {
                if (!firstJson) std::cout << ",\n";
                std::wcout << L"  {\n    \"HotFixID\": \"" << id << L"\",\n"
                           << L"    \"InstalledOn\": \"" << date << L"\",\n"
                           << L"    \"Description\": \"" << desc << L"\"\n  }";
                firstJson = false;
            }
            else {
                std::wcout << L"\033[33m[" << id << L"]\033[0m " << date << L" - " << desc << L"\n";
            }
        }

        VariantClear(&vtHotFixID);
        VariantClear(&vtDate);
        VariantClear(&vtDesc);
        pClassObject->Release();
    }

    if (asJson) std::cout << "\n]\n";
    if (countOnly) std::cout << "\033[36m[Total]\033[0m " << count << " hotfix(es) matched filters.\n";

    pEnumerator->Release();
    pServices->Release();
    pLocator->Release();
    CoUninitialize();
}

bool VerifyDriverSignature(const std::wstring& driverPath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = driverPath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = 0;
    trustData.hWVTStateData = nullptr;
    trustData.pwszURLReference = nullptr;
    trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE;
    trustData.dwUIContext = 0;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);
    return (status == ERROR_SUCCESS);
}

// Command: Diagnostics -> Drivers
void CmdDiagnosticsDrivers(const std::string& args) {
    std::istringstream iss(args);
    std::vector<std::string> argv;
    for (std::string arg; iss >> arg;) argv.push_back(arg);

    const bool filterUnsigned = HasFlag(argv, "--unsigned");
    const bool listAll = HasFlag(argv, "--all") || (!filterUnsigned && !HasFlag(argv, "--json"));
    const bool outputJson = HasFlag(argv, "--json");

    // Enumerate loaded drivers
    std::vector<LPVOID> drivers(1024);
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers.data(), (DWORD)(drivers.size() * sizeof(LPVOID)), &cbNeeded)) {
        std::cerr << "\033[31m[Error]\033[0m Failed to enumerate device drivers.\n";
        return;
    }

    const size_t driverCount = cbNeeded / sizeof(LPVOID);
    if (driverCount > drivers.size()) drivers.resize(driverCount);

    // Helper lambda: get driver file path
    auto GetDriverPath = [](LPVOID baseAddr) -> std::wstring {
        wchar_t path[MAX_PATH] = { 0 };
        if (GetDeviceDriverFileNameW(baseAddr, path, MAX_PATH)) {
            return std::wstring(path);
        }
        return L"";
    };

    // Output header
    if (!outputJson)
        std::cout << "\033[36m[Diagnostics]\033[0m Loaded Device Drivers:\n";
    else
        std::cout << "[\n";

    int totalDrivers = 0;
    int unsignedDrivers = 0;
    bool firstJson = true;

    for (size_t i = 0; i < driverCount; ++i) {
        std::wstring driverPath = GetDriverPath(drivers[i]);
        if (driverPath.empty()) continue;

        // Normalize path for proper signature validation
        std::wstring normalizedPath = NormalizeDriverPath(driverPath);

        bool isSigned = VerifyDriverSignature(normalizedPath);
        if (filterUnsigned && isSigned) continue;

        ++totalDrivers;
        if (!isSigned) ++unsignedDrivers;

        // Extract file name
        std::wstring filename;
        size_t pos = driverPath.find_last_of(L"\\/");
        filename = (pos != std::wstring::npos) ? driverPath.substr(pos + 1) : driverPath;

        if (!outputJson) {
            std::wcout << (isSigned ? L"\033[32m" : L"\033[31m")
                << filename << (isSigned ? L" [Signed]" : L" [Unsigned]") << L"\033[0m\n"
                << L"  Path: " << driverPath << L"\n";
        } else {
            if (!firstJson) std::cout << ",\n";
            firstJson = false;

            std::wcout << L"  {\n"
                       << L"    \"FileName\": \"" << filename << L"\",\n"
                       << L"    \"Path\": \"" << driverPath << L"\",\n"
                       << L"    \"Signed\": " << (isSigned ? "true" : "false") << L"\n"
                       << L"  }";
        }
    }

    if (outputJson) std::cout << "\n]\n";

    if (!outputJson) {
        std::cout << "\033[36m[Summary]\033[0m Total Drivers Scanned: " << totalDrivers
                  << ", Unsigned Drivers: " << unsignedDrivers << "\n";
    }
}

void CmdDiagnosticsDefender(const std::string& cmdline) {
    std::vector<std::string> args;
    std::istringstream ss(cmdline);
    for (std::string arg; ss >> arg;) args.push_back(arg);

    const bool asJson = HasFlag(args, "--json");

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) { std::cerr << "[Error] COM init failed.\n"; return; }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr)) { std::cerr << "[Error] COM security init failed.\n"; CoUninitialize(); return; }

    IWbemLocator* pLocator = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr)) { std::cerr << "[Error] WbemLocator create failed.\n"; CoUninitialize(); return; }

    IWbemServices* pServices = nullptr;
    hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"), nullptr, nullptr, 0, 0, 0, nullptr, &pServices);
    if (FAILED(hr)) { std::cerr << "[Error] WMI connect failed.\n"; pLocator->Release(); CoUninitialize(); return; }

    hr = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    if (FAILED(hr)) { std::cerr << "[Error] CoSetProxyBlanket failed.\n"; pServices->Release(); pLocator->Release(); CoUninitialize(); return; }

    // 1️⃣ Get general status
    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pServices->ExecQuery(
        bstr_t(L"WQL"),
        bstr_t(L"SELECT * FROM MSFT_MpComputerStatus"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);
    if (FAILED(hr)) { std::cerr << "[Error] Defender query failed.\n"; pServices->Release(); pLocator->Release(); CoUninitialize(); return; }

    IWbemClassObject* pClassObject = nullptr;
    ULONG uReturn = 0;
    if (!asJson)
    std::cout << "\033[1;34m[Diagnostics]\033[0m Windows Defender Status:\n";
else
    std::cout << "[\n";

    bool firstJson = true;

    while (pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn) == S_OK) {
        VARIANT vtRealTime, vtSignature, vtLastUpdate, vtLastScan, vtTamper, vtCloud, vtBehavior, vtAMEnabled, vtEDREnabled;
        VariantInit(&vtRealTime); VariantInit(&vtSignature); VariantInit(&vtLastUpdate);
        VariantInit(&vtLastScan); VariantInit(&vtTamper); VariantInit(&vtCloud); VariantInit(&vtBehavior);
        VariantInit(&vtAMEnabled); VariantInit(&vtEDREnabled);

        pClassObject->Get(L"RealTimeProtectionEnabled", 0, &vtRealTime, nullptr, nullptr);
        pClassObject->Get(L"AntivirusSignatureVersion", 0, &vtSignature, nullptr, nullptr);
        pClassObject->Get(L"AntivirusSignatureLastUpdated", 0, &vtLastUpdate, nullptr, nullptr);
        pClassObject->Get(L"QuickScanEndTime", 0, &vtLastScan, nullptr, nullptr);
        pClassObject->Get(L"TamperProtectionEnabled", 0, &vtTamper, nullptr, nullptr);
        pClassObject->Get(L"CloudEnabled", 0, &vtCloud, nullptr, nullptr);
        pClassObject->Get(L"BehaviorMonitorEnabled", 0, &vtBehavior, nullptr, nullptr);
        pClassObject->Get(L"AMEnabled", 0, &vtAMEnabled, nullptr, nullptr);
        pClassObject->Get(L"EDREnabled", 0, &vtEDREnabled, nullptr, nullptr);

        bool realtime = vtRealTime.vt == VT_BOOL ? (vtRealTime.boolVal == VARIANT_TRUE) : false;
        std::wstring signature = vtSignature.vt == VT_BSTR && vtSignature.bstrVal ? vtSignature.bstrVal : L"";
        std::wstring lastUpdate = vtLastUpdate.vt == VT_BSTR && vtLastUpdate.bstrVal ? vtLastUpdate.bstrVal : L"";
        std::wstring lastScan = vtLastScan.vt == VT_BSTR && vtLastScan.bstrVal ? vtLastScan.bstrVal : L"";
        bool tamper = vtTamper.vt == VT_BOOL ? (vtTamper.boolVal == VARIANT_TRUE) : false;
        bool cloud = vtCloud.vt == VT_BOOL ? (vtCloud.boolVal == VARIANT_TRUE) : false;
        bool behavior = vtBehavior.vt == VT_BOOL ? (vtBehavior.boolVal == VARIANT_TRUE) : false;
        bool amEnabled = vtAMEnabled.vt == VT_BOOL ? (vtAMEnabled.boolVal == VARIANT_TRUE) : false;
        bool edrEnabled = vtEDREnabled.vt == VT_BOOL ? (vtEDREnabled.boolVal == VARIANT_TRUE) : false;

        if (!asJson) {
            std::wcout << L"\033[36m  Real-Time Protection:\033[0m " 
                    << (realtime ? L"\033[32mEnabled\033[0m" : L"\033[31mDisabled\033[0m") << L"\n";
            std::wcout << L"\033[36m  Signature Version:\033[0m " << signature << L"\n";
            std::wcout << L"\033[36m  Signature Last Updated:\033[0m " << lastUpdate << L"\n";
            std::wcout << L"\033[36m  Last Quick Scan End:\033[0m " << lastScan << L"\n";
            std::wcout << L"\033[36m  Tamper Protection:\033[0m " 
                    << (tamper ? L"\033[32mEnabled\033[0m" : L"\033[31mDisabled\033[0m") << L"\n";
            std::wcout << L"\033[36m  Cloud Protection:\033[0m " 
                    << (cloud ? L"\033[32mEnabled\033[0m" : L"\033[31mDisabled\033[0m") << L"\n";
            std::wcout << L"\033[36m  Behavior Monitoring:\033[0m " 
                    << (behavior ? L"\033[32mEnabled\033[0m" : L"\033[31mDisabled\033[0m") << L"\n";
            std::wcout << L"\033[36m  Antivirus (AM) Enabled:\033[0m " 
                    << (amEnabled ? L"\033[32mYes\033[0m" : L"\033[31mNo\033[0m") << L"\n";
            std::wcout << L"\033[36m  EDR Enabled:\033[0m " 
                    << (edrEnabled ? L"\033[32mYes\033[0m" : L"\033[31mNo\033[0m") << L"\n";
        } else {
            if (!firstJson) std::cout << ",\n";
            firstJson = false;
            std::wcout << L"  {\n"
                       << L"    \"RealTimeProtection\": " << (realtime ? "true" : "false") << L",\n"
                       << L"    \"SignatureVersion\": \"" << signature << L"\",\n"
                       << L"    \"SignatureLastUpdated\": \"" << lastUpdate << L"\",\n"
                       << L"    \"LastQuickScanEnd\": \"" << lastScan << L"\",\n"
                       << L"    \"TamperProtection\": " << (tamper ? "true" : "false") << L",\n"
                       << L"    \"CloudProtection\": " << (cloud ? "true" : "false") << L",\n"
                       << L"    \"BehaviorMonitoring\": " << (behavior ? "true" : "false") << L",\n"
                       << L"    \"AntivirusEnabled\": " << (amEnabled ? "true" : "false") << L",\n"
                       << L"    \"EDREnabled\": " << (edrEnabled ? "true" : "false") << L"\n"
                       << L"  }";
        }

        VariantClear(&vtRealTime); VariantClear(&vtSignature); VariantClear(&vtLastUpdate);
        VariantClear(&vtLastScan); VariantClear(&vtTamper); VariantClear(&vtCloud);
        VariantClear(&vtBehavior); VariantClear(&vtAMEnabled); VariantClear(&vtEDREnabled);
        pClassObject->Release();
    }

    if (asJson) std::cout << "\n]\n";

    pEnumerator->Release();
    pServices->Release();
    pLocator->Release();
    CoUninitialize();

    // 2️⃣ Optional: Query last detected threat
    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        IWbemLocator* pThreatLocator = nullptr;
        hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pThreatLocator);
        if (SUCCEEDED(hr)) {
            IWbemServices* pThreatServices = nullptr;
            if (SUCCEEDED(pThreatLocator->ConnectServer(_bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"), nullptr, nullptr, 0, 0, 0, nullptr, &pThreatServices))) {
                CoSetProxyBlanket(pThreatServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                  RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                  nullptr, EOAC_NONE);

                IEnumWbemClassObject* pThreatEnum = nullptr;
                if (SUCCEEDED(pThreatServices->ExecQuery(bstr_t(L"WQL"),
                    bstr_t(L"SELECT * FROM MSFT_MpThreatDetection WHERE ActionSuccess = TRUE"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    nullptr, &pThreatEnum))) {
                    
                    IWbemClassObject* pThreat = nullptr;
                    ULONG uReturn = 0;
                    if (pThreatEnum->Next(WBEM_INFINITE, 1, &pThreat, &uReturn) == S_OK) {
                        VARIANT vtThreat, vtPath, vtTime;
                        VariantInit(&vtThreat); VariantInit(&vtPath); VariantInit(&vtTime);

                        pThreat->Get(L"ThreatName", 0, &vtThreat, nullptr, nullptr);
                        pThreat->Get(L"Resources", 0, &vtPath, nullptr, nullptr);
                        pThreat->Get(L"ExecutionTime", 0, &vtTime, nullptr, nullptr);

                        if (!asJson) {
                            std::wcout << L"  Last Detected Threat: " 
                                       << (vtThreat.vt == VT_BSTR && vtThreat.bstrVal ? vtThreat.bstrVal : L"N/A") << L"\n";
                            std::wcout << L"  Threat Path: "
                                       << (vtPath.vt == VT_BSTR && vtPath.bstrVal ? vtPath.bstrVal : L"N/A") << L"\n";
                            std::wcout << L"  Detection Time: "
                                       << (vtTime.vt == VT_BSTR && vtTime.bstrVal ? vtTime.bstrVal : L"N/A") << L"\n";
                        }

                        VariantClear(&vtThreat); VariantClear(&vtPath); VariantClear(&vtTime);
                        pThreat->Release();
                    }
                    pThreatEnum->Release();
                }
                pThreatServices->Release();
            }
            pThreatLocator->Release();
        }
        CoUninitialize();
    }
}

void CmdDiagnosticsTasks(const std::string& cmdline) {
    std::vector<std::string> args;
    std::istringstream ss(cmdline);
    for (std::string arg; ss >> arg;) args.push_back(arg);

    const bool asJson = HasFlag(args, "--json");
    const bool onlyEnabled = HasFlag(args, "--enabled");
    const bool onlyDisabled = HasFlag(args, "--disabled");
    const bool showLastRun = HasFlag(args, "--last-run");

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m COM initialization failed.\n";
        return;
    }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m COM security initialization failed.\n";
        CoUninitialize();
        return;
    }

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m Failed to create TaskService instance.\n";
        CoUninitialize();
        return;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m Failed to connect to Task Scheduler.\n";
        pService->Release();
        CoUninitialize();
        return;
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m Failed to get root task folder.\n";
        pService->Release();
        CoUninitialize();
        return;
    }

    IRegisteredTaskCollection* pTaskCollection = nullptr;
    hr = pRootFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
    if (FAILED(hr)) {
        std::cerr << "\033[31m[Error]\033[0m Failed to enumerate tasks.\n";
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return;
    }

    LONG count = 0;
    pTaskCollection->get_Count(&count);

    if (!asJson) std::cout << "\033[1;34m[Diagnostics]\033[0m Scheduled Tasks:\n";
    else std::cout << "[\n";

    bool firstJson = true;
    for (LONG i = 0; i < count; ++i) {
        IRegisteredTask* pTask = nullptr;
        pTaskCollection->get_Item(_variant_t(i + 1), &pTask);

        BSTR name; pTask->get_Name(&name);
        BSTR path; pTask->get_Path(&path);

        VARIANT_BOOL enabled; pTask->get_Enabled(&enabled);

        if ((onlyEnabled && !enabled) || (onlyDisabled && enabled)) {
            pTask->Release();
            continue;
        }

        IRunningTask* pRunningTask = nullptr;
        // Last run time
        BSTR lastRunTime = nullptr;
        if (showLastRun) {
            DATE lastRunDate;
            hr = pTask->get_LastRunTime(&lastRunDate);
            if (SUCCEEDED(hr)) {
                SYSTEMTIME st;
                VariantTimeToSystemTime(lastRunDate, &st);
                wchar_t buffer[64];
                swprintf(buffer, 64, L"%02d-%02d-%04d %02d:%02d:%02d",
                        st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
                lastRunTime = SysAllocString(buffer);
            } else {
                lastRunTime = SysAllocString(L"N/A");
            }
        }
        if (!asJson) {
            std::wcout << L"  Task: \033[36m" << name << L"\033[0m\n";
            std::wcout << L"    Path: " << path << L"\n";
            std::wcout << L"    Status: " << (enabled ? L"\033[32mEnabled\033[0m" : L"\033[31mDisabled\033[0m") << L"\n";
            if (showLastRun) std::wcout << L"    Last Run: " << lastRunTime << L"\n";
        } else {
            if (!firstJson) std::cout << ",\n";
            firstJson = false;
            std::wcout << L"  {\n"
                       << L"    \"Name\": \"" << name << L"\",\n"
                       << L"    \"Path\": \"" << path << L"\",\n"
                       << L"    \"Enabled\": " << (enabled ? "true" : "false");
            if (showLastRun) std::wcout << L",\n    \"LastRun\": \"" << lastRunTime << L"\"";
            std::wcout << L"\n  }";
        }

        if (showLastRun) SysFreeString(lastRunTime);
        pTask->Release();
    }

    if (asJson) std::cout << "\n]\n";

    pTaskCollection->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
}

void CmdDiagnosticsHelp(const std::string& args) {
    std::cout << "\033[36m[Diagnostics Help]\033[0m Available subcommands:\n"
              << "  integrity   - Check integrity of installed Windows hotfixes\n"
              << "                Options:\n"
              << "                  --json            Output results in JSON format\n"
              << "                  --count           Only output the count of matching hotfixes\n"
              << "                  --hotfixid=ID     Filter by HotFixID substring\n"
              << "                  --after=YYYY-MM-DD  Filter hotfixes installed on or after the date\n"
              << "  drivers     - List loaded device drivers and their signature status\n"
              << "                Options:\n"
              << "                  --unsigned       Only list unsigned drivers\n"
              << "                  --all            List all drivers (default behavior)\n"
              << "                  --json           Output results in JSON format\n"
              << "  defender    - Check Windows Defender status\n"
              << "                Options:\n"
              << "                  --json           Output results in JSON format\n"
              << "  tasks       - List scheduled tasks and their status\n"
              << "                Options:\n"
              << "                  --enabled        Only list enabled tasks\n"
              << "                  --disabled       Only list disabled tasks\n"
              << "                  --last-run       Show last run time of tasks\n"
              << "                  --json           Output results in JSON format\n";
}