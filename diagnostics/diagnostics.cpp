#include <windows.h>
#include <psapi.h>
#include <setupapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <comdef.h>
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

bool HasFlag(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}

std::string GetArgValue(const std::vector<std::string>& args, const std::string& prefix) {
    for (const auto& arg : args) {
        if (arg.rfind(prefix, 0) == 0) {
            return arg.substr(prefix.length());
        }
    }
    return "";
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
    // Setup WINTRUST_FILE_INFO
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = driverPath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    // Setup WINTRUST_DATA
    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = 0;
    trustData.hWVTStateData = nullptr;
    trustData.pwszURLReference = nullptr;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.dwUIContext = 0;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);
    return (status == ERROR_SUCCESS);
}

void CmdDiagnosticsDrivers(const std::string& args) {
    // Parse args
    std::istringstream iss(args);
    std::vector<std::string> argv;
    for (std::string arg; iss >> arg;) argv.push_back(arg);

    const bool filterUnsigned = HasFlag(argv, "--unsigned");
    const bool listAll = HasFlag(argv, "--all") || (!filterUnsigned && !HasFlag(argv, "--json"));
    const bool outputJson = HasFlag(argv, "--json");

    // Enumerate device drivers
    std::vector<LPVOID> drivers(1024);
    DWORD cbNeeded = 0;

    if (!EnumDeviceDrivers(drivers.data(), (DWORD)(drivers.size() * sizeof(LPVOID)), &cbNeeded)) {
        std::cerr << "\033[31m[Error]\033[0m Failed to enumerate device drivers.\n";
        return;
    }

    const size_t driverCount = cbNeeded / sizeof(LPVOID);
    if (driverCount > drivers.size()) drivers.resize(driverCount);

    // Helper lambda to get driver path
    auto GetDriverPath = [](LPVOID baseAddr) -> std::wstring {
        wchar_t path[MAX_PATH] = {0};
        if (GetDeviceDriverFileNameW(baseAddr, path, MAX_PATH)) {
            return std::wstring(path);
        }
        return L"";
    };

    // Output preparation
    if (!outputJson) {
        std::cout << "\033[36m[Diagnostics]\033[0m Loaded Device Drivers:\n";
    } else {
        std::cout << "[\n";
    }

    int totalDrivers = 0;
    int unsignedDrivers = 0;
    bool firstJson = true;

    for (size_t i = 0; i < driverCount; ++i) {
        std::wstring driverPath = GetDriverPath(drivers[i]);
        if (driverPath.empty()) continue;

        bool isSigned = VerifyDriverSignature(driverPath);

        // Skip if filtering unsigned and this one is signed
        if (filterUnsigned && isSigned) continue;

        ++totalDrivers;
        if (!isSigned) ++unsignedDrivers;

        // Extract driver file name from full path
        std::wstring filename;
        size_t pos = driverPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) filename = driverPath.substr(pos + 1);
        else filename = driverPath;

        if (!outputJson) {
            // Colored output
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
