#include <windows.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <stdexcept>

#pragma comment(lib, "wtsapi32.lib")

// RAII helper for HANDLE.
class HandleWrapper {
public:
    HandleWrapper(HANDLE h = nullptr) : handle(h) {}
    ~HandleWrapper() { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    HANDLE get() const { return handle; }
    void reset(HANDLE h = nullptr) {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
        handle = h;
    }
private:
    HANDLE handle;
};

// Logging function: writes messages to a log file with a timestamp.
void LogMessage(const std::wstring& msg) {
    try {
        std::wofstream logFile(L"ServiceUIClone.log", std::ios::app);
        if (logFile) {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm timeInfo;
            localtime_s(&timeInfo, &now_c);
            // Format: [YYYY-MM-DD HH:MM:SS]
            logFile << L"[" << std::put_time(&timeInfo, L"%Y-%m-%d %H:%M:%S")
                << L"] " << msg << std::endl;
        }
    }
    catch (...) {
        // In production, handle logging exceptions appropriately.
    }
}

// Helper: Print error messages with details.
void PrintError(const TCHAR* msg) {
    DWORD errCode = GetLastError();
    LPTSTR errorText = nullptr;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errorText,
        0,
        nullptr
    );
    std::wcerr << msg << _T(" Error Code: ") << errCode;
    std::wstring logStr = msg;
    logStr += L" Error Code: " + std::to_wstring(errCode);
    if (errorText) {
        std::wcerr << _T(" - ") << errorText;
        logStr += L" - ";
        logStr += errorText;
        LocalFree(errorText);
    }
    std::wcerr << std::endl;
    LogMessage(logStr);
}

// Helper: Enable a privilege in the current process token.
bool EnablePrivilege(LPCTSTR privilegeName) {
    HandleWrapper hToken;
    HANDLE tokenHandle = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
        return false;
    hToken.reset(tokenHandle);

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, privilegeName, &luid))
        return false;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr))
        return false;

    return (GetLastError() == ERROR_SUCCESS);
}

// Helper: Trim whitespace from both ends of a string.
std::wstring Trim(const std::wstring& str) {
    const wchar_t* whitespace = L" \t\n\r";
    size_t start = str.find_first_not_of(whitespace);
    if (start == std::wstring::npos)
        return L"";
    size_t end = str.find_last_not_of(whitespace);
    return str.substr(start, end - start + 1);
}

int _tmain(int argc, TCHAR* argv[])
{
    try {
        bool waitForProcess = false;
        int argStart = 1;

        // Optionally support a "/wait" or "-wait" flag as the first argument.
        if (argc > 1 &&
            (_tcscmp(argv[1], _T("/wait")) == 0 || _tcscmp(argv[1], _T("-wait")) == 0)) {
            waitForProcess = true;
            argStart = 2;
        }

        // Validate input: at least one argument (after optional /wait) is required.
        if (argc < argStart + 1) {
            std::wcerr << _T("Usage: ServiceUIClone.exe [/wait] <command line to launch>") << std::endl;
            LogMessage(L"Insufficient arguments provided.");
            return 1;
        }

        // Combine arguments into a single command-line string.
        std::wstring commandLine;
        for (int i = argStart; i < argc; ++i) {
            if (i > argStart)
                commandLine += L" ";
            commandLine += argv[i];
        }

        // Trim the combined command line.
        commandLine = Trim(commandLine);
        if (commandLine.empty()) {
            std::wcerr << _T("Error: The command line is empty after trimming.") << std::endl;
            LogMessage(L"Empty command line after trimming.");
            return 1;
        }

        // Optionally, enforce a maximum length.
        const size_t MAX_CMDLINE_LENGTH = 1024;
        if (commandLine.size() > MAX_CMDLINE_LENGTH) {
            std::wcerr << _T("Error: Command line exceeds maximum allowed length.") << std::endl;
            LogMessage(L"Command line too long.");
            return 1;
        }

        LogMessage(L"Command line to launch: " + commandLine);

        // Call ImpersonateSelf to obtain a thread token with necessary privileges.
        if (!ImpersonateSelf(SecurityImpersonation)) {
            PrintError(_T("ImpersonateSelf failed."));
            return 1;
        }
        LogMessage(L"ImpersonateSelf called successfully.");

        // Step 1: Get the active console session ID.
        DWORD sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF) {
            PrintError(_T("Failed to get active console session ID."));
            return 1;
        }
        {
            std::wstringstream ss;
            ss << L"Active console session ID: " << sessionId;
            LogMessage(ss.str());
        }

        // Step 2: Open the current process token (should be SYSTEM).
        HANDLE hProcessTokenRaw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hProcessTokenRaw)) {
            PrintError(_T("OpenProcessToken failed."));
            return 1;
        }
        HandleWrapper hProcessToken(hProcessTokenRaw);
        LogMessage(L"Opened process token successfully.");

        // Step 3: Duplicate the token to create a primary token.
        HANDLE hDupTokenRaw = nullptr;
        // Use SecurityDelegation so the duplicated token carries all privileges.
        if (!DuplicateTokenEx(hProcessToken.get(), MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenPrimary, &hDupTokenRaw)) {
            PrintError(_T("DuplicateTokenEx failed."));
            return 1;
        }
        HandleWrapper hDupToken(hDupTokenRaw);
        LogMessage(L"Duplicated token successfully.");

        // Revert to self since the token has been duplicated.
        if (!RevertToSelf()) {
            PrintError(_T("RevertToSelf failed."));
            // Continue even if reverting fails.
        }
        else {
            LogMessage(L"RevertToSelf succeeded.");
        }

        // Step 4: Set the duplicated token's session ID to the active console session.
        if (!SetTokenInformation(hDupToken.get(), TokenSessionId, &sessionId, sizeof(sessionId))) {
            PrintError(_T("SetTokenInformation failed."));
            return 1;
        }
        LogMessage(L"Token session ID set to active console session.");

        // Step 5: Enable required privileges.
        if (!EnablePrivilege(SE_INCREASE_QUOTA_NAME)) {
            PrintError(_T("Failed to enable SeIncreaseQuotaPrivilege."));
            return 1;
        }
        if (!EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
            PrintError(_T("Failed to enable SeAssignPrimaryTokenPrivilege."));
            return 1;
        }
        if (!EnablePrivilege(_T("SeTcbPrivilege"))) {
            PrintError(_T("Failed to enable SeTcbPrivilege. The process must run as SYSTEM."));
            return 1;
        }
        LogMessage(L"Required privileges enabled successfully.");

        // Step 6: Prepare STARTUPINFO and PROCESS_INFORMATION.
        STARTUPINFO si = {};
        si.cb = sizeof(si);
        si.lpDesktop = const_cast<LPTSTR>(_T("winsta0\\default"));

        PROCESS_INFORMATION pi = {};

        // Create a writable copy of the command-line.
        size_t bufSize = commandLine.size() + 1;
        TCHAR* cmdLine = new TCHAR[bufSize];
        _tcscpy_s(cmdLine, bufSize, commandLine.c_str());

        LogMessage(L"Attempting to launch process with CreateProcessAsUser.");

        // Step 7: Create the process using the modified SYSTEM token.
        BOOL result = CreateProcessAsUser(
            hDupToken.get(),    // SYSTEM token adjusted to active session.
            nullptr,            // Application name (NULL when using command line).
            cmdLine,            // Command line to execute.
            nullptr,            // Process security attributes.
            nullptr,            // Thread security attributes.
            FALSE,              // Do not inherit handles.
            0,                  // No creation flags.
            nullptr,            // Use parent's environment.
            nullptr,            // Use parent's current directory.
            &si,                // STARTUPINFO.
            &pi                 // PROCESS_INFORMATION.
        );

        delete[] cmdLine;

        if (!result) {
            PrintError(_T("CreateProcessAsUser failed."));
            return 1;
        }

        {
            std::wstringstream ss;
            ss << L"Process launched successfully in session " << sessionId
                << L". Process ID: " << pi.dwProcessId;
            LogMessage(ss.str());
            std::wcout << ss.str() << std::endl;
        }

        // If /wait flag was specified, wait for the process to terminate.
        if (waitForProcess) {
            LogMessage(L"Waiting for the launched process to exit...");
            DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE);
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
                    std::wstringstream ss;
                    ss << L"Launched process exited with code: " << exitCode;
                    LogMessage(ss.str());
                    std::wcout << ss.str() << std::endl;
                    // Close handles before returning.
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return exitCode;
                }
                else {
                    PrintError(_T("Failed to get exit code from process."));
                }
            }
            else {
                PrintError(_T("WaitForSingleObject failed."));
            }
        }

        // Clean up process and thread handles.
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    catch (const std::exception& ex) {
        std::wcerr << _T("Exception: ") << ex.what() << std::endl;
        LogMessage(std::wstring(L"Exception: ") + std::wstring(ex.what(), ex.what() + strlen(ex.what())));
        return 1;
    }
    return 0;
}
