#include <windows.h>
#include <tchar.h>
#include <comdef.h>
#include <wbemidl.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <string>
#include <iostream>

#include "resource.h"  // Defines IDI_BITLOCKERICON

#pragma comment(lib, "wbemuuid.lib")

// Control IDs
#define IDC_LABEL_MAIN     1001
#define IDC_LABEL_SUB      1002
#define IDC_LABEL_NEWPIN   1003
#define IDC_LABEL_RETYPE   1004
#define IDC_EDIT_NEWPIN    1101
#define IDC_EDIT_RETYPE    1102
#define IDC_BUTTON_SETPIN  1201
#define IDC_BUTTON_CANCEL  1202
#define IDC_STATIC_ICON    1301

// Global font handles.
HFONT g_hFontNormal = nullptr;
HFONT g_hFontHeading = nullptr;

//
// LogMessage: Writes a message with a timestamp to a log file.
// The log file is written to C:\Temp\BitLockerPINUI.log (ensure the directory exists)
//
void LogMessage(const std::wstring &msg)
{
    try {
        std::wofstream logFile(L"C:\\Temp\\BitLockerPINUI.log", std::ios::app);
        if (logFile.is_open())
        {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm timeInfo;
            localtime_s(&timeInfo, &now_c);
            logFile << L"[" << std::put_time(&timeInfo, L"%Y-%m-%d %H:%M:%S")
                    << L"] " << msg << std::endl;
            logFile.close();
        }
    }
    catch (...) {
        // In production, handle exceptions appropriately.
    }
}

//
// PrintError: Prints an error message (with system error text) to the console and logs it.
//
void PrintError(const TCHAR* msg)
{
    DWORD errCode = GetLastError();
    LPTSTR errorText = nullptr;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  nullptr, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&errorText, 0, nullptr);
    std::wcerr << msg << _T(" Error Code: ") << errCode;
    std::wstring logStr = msg;
    logStr += L" Error Code: " + std::to_wstring(errCode);
    if (errorText)
    {
        std::wcerr << _T(" - ") << errorText;
        logStr += L" - ";
        logStr += errorText;
        LocalFree(errorText);
    }
    std::wcerr << std::endl;
    LogMessage(logStr);
}

//
// Trim: Trims whitespace from both ends of a string.
//
std::wstring Trim(const std::wstring &str)
{
    const wchar_t* whitespace = L" \t\n\r";
    size_t start = str.find_first_not_of(whitespace);
    if (start == std::wstring::npos)
        return L"";
    size_t end = str.find_last_not_of(whitespace);
    return str.substr(start, end - start + 1);
}

//
// ValidatePIN: Returns true if the PIN is numeric and between 8 and 20 characters.
//
bool ValidatePIN(const std::wstring &pin)
{
    if (pin.length() < 8 || pin.length() > 20)
        return false;
    for (wchar_t ch : pin)
    {
        if (!iswdigit(ch))
            return false;
    }
    return true;
}

//
// SetBitLockerPinWMI: Uses WMI to call AddKeyProtector on drive C:
// TPM+PIN is represented by KeyProtectorType = 2.
// Returns true on success; false otherwise. The actual PIN is not logged.
//
bool SetBitLockerPinWMI(const std::wstring& pin)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        LogMessage(L"CoInitializeEx failed.");
        return false;
    }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr))
    {
        LogMessage(L"CoInitializeSecurity failed.");
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr))
    {
        LogMessage(L"Failed to create IWbemLocator object.");
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption"),
                              nullptr, nullptr, 0, 0, nullptr, 0, &pSvc);
    if (FAILED(hr))
    {
        LogMessage(L"Could not connect to WMI namespace.");
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                           nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    if (FAILED(hr))
    {
        LogMessage(L"CoSetProxyBlanket failed.");
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Query for the BitLocker volume for drive C:
    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(_bstr_t(L"WQL"),
                         _bstr_t(L"SELECT * FROM Win32_EncryptableVolume WHERE DeviceID = \"C:\""),
                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                         nullptr, &pEnumerator);
    if (FAILED(hr))
    {
        LogMessage(L"Query for Win32_EncryptableVolume failed.");
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pVolume = nullptr;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pVolume, &uReturn);
    if (FAILED(hr) || uReturn == 0)
    {
        LogMessage(L"No BitLocker volume found for drive C:.");
        if (pEnumerator) pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }
    pEnumerator->Release();

    // Get the __PATH property for the volume.
    VARIANT varPath;
    VariantInit(&varPath);
    hr = pVolume->Get(_bstr_t(L"__PATH"), 0, &varPath, nullptr, nullptr);
    if (FAILED(hr))
    {
        LogMessage(L"Failed to get volume __PATH.");
        pVolume->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Get the Win32_EncryptableVolume class definition.
    IWbemClassObject* pClass = nullptr;
    hr = pSvc->GetObject(_bstr_t(L"Win32_EncryptableVolume"), 0, nullptr, &pClass, nullptr);
    if (FAILED(hr))
    {
        LogMessage(L"Failed to get Win32_EncryptableVolume class definition.");
        VariantClear(&varPath);
        pVolume->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Get input parameters definition for the AddKeyProtector method.
    IWbemClassObject* pInParamsDefinition = nullptr;
    hr = pClass->GetMethod(L"AddKeyProtector", 0, &pInParamsDefinition, nullptr);
    pClass->Release();
    if (FAILED(hr))
    {
        LogMessage(L"Failed to retrieve AddKeyProtector method definition.");
        VariantClear(&varPath);
        pVolume->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pInParams = nullptr;
    hr = pInParamsDefinition->SpawnInstance(0, &pInParams);
    pInParamsDefinition->Release();
    if (FAILED(hr))
    {
        LogMessage(L"Failed to spawn AddKeyProtector input params instance.");
        VariantClear(&varPath);
        pVolume->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Set KeyProtectorType = 2 (TPM+PIN)
    VARIANT varProtectorType;
    VariantInit(&varProtectorType);
    varProtectorType.vt = VT_UINT;
    varProtectorType.uintVal = 2;
    hr = pInParams->Put(L"KeyProtectorType", 0, &varProtectorType, 0);
    VariantClear(&varProtectorType);
    if (FAILED(hr))
    {
        LogMessage(L"Failed to set KeyProtectorType.");
        pInParams->Release();
        VariantClear(&varPath);
        pVolume->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Set the PIN parameter (do not log the actual PIN).
    VARIANT varPin;
    VariantInit(&varPin);
    varPin.vt = VT_BSTR;
    varPin.bstrVal = SysAllocString(pin.c_str());
    hr = pInParams->Put(L"Pin", 0, &varPin, 0);
    VariantClear(&varPin);
    if (FAILED(hr))
    {
        LogMessage(L"Failed to set Pin parameter.");
        pInParams->Release();
        VariantClear(&varPath);
        pVolume->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Execute the AddKeyProtector method.
    IWbemClassObject* pOutParams = nullptr;
    BSTR methodName = SysAllocString(L"AddKeyProtector");
    hr = pSvc->ExecMethod(varPath.bstrVal, methodName, 0, nullptr, pInParams, &pOutParams, nullptr);
    SysFreeString(methodName);
    bool success = false;
    if (SUCCEEDED(hr))
    {
        VARIANT varReturn;
        VariantInit(&varReturn);
        hr = pOutParams->Get(L"ReturnValue", 0, &varReturn, nullptr, nullptr);
        if (SUCCEEDED(hr) && varReturn.vt == VT_I4 && varReturn.intVal == 0)
        {
            success = true;
        }
        VariantClear(&varReturn);
        pOutParams->Release();
    }
    else
    {
        LogMessage(L"ExecMethod for AddKeyProtector failed.");
    }

    // Cleanup
    pInParams->Release();
    VariantClear(&varPath);
    pVolume->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return success;
}

//
// WindowProc: Creates the modern UI with a logo, headings, PIN input fields, and buttons.
// Performs robust input validation and calls SetBitLockerPinWMI to set the BitLocker PIN.
//
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static HWND hEditNewPin = nullptr, hEditRePin = nullptr, hIconCtrl = nullptr;
    switch (uMsg)
    {
        case WM_CREATE:
        {
            HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
            HDC hdc = GetDC(hwnd);
            int dpiY = GetDeviceCaps(hdc, LOGPIXELSY);
            ReleaseDC(hwnd, hdc);
            g_hFontNormal = CreateFont(-MulDiv(9, dpiY, 72), 0, 0, 0,
                                       FW_NORMAL, FALSE, FALSE, FALSE,
                                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                       CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                       DEFAULT_PITCH | FF_DONTCARE, _T("Segoe UI"));
            g_hFontHeading = CreateFont(-MulDiv(11, dpiY, 72), 0, 0, 0,
                                        FW_BOLD, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                        CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                        DEFAULT_PITCH | FF_DONTCARE, _T("Segoe UI"));

            // Load the icon resource.
            HICON hIcon = (HICON)LoadImage(hInst, MAKEINTRESOURCE(IDI_BITLOCKERICON),
                                           IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
            if (!hIcon)
            {
                PrintError(_T("Failed to load icon resource."));
            }
            hIconCtrl = CreateWindow(_T("STATIC"), nullptr,
                                     WS_CHILD | WS_VISIBLE | SS_ICON,
                                     10, 10, 32, 32,
                                     hwnd, (HMENU)IDC_STATIC_ICON, hInst, nullptr);
            if (hIconCtrl && hIcon)
            {
                SendMessage(hIconCtrl, STM_SETICON, (WPARAM)hIcon, 0);
            }

            // Main heading.
            HWND hLabelMain = CreateWindow(_T("STATIC"), _T("Set BitLocker startup PIN"),
                                           WS_CHILD | WS_VISIBLE,
                                           50, 15, 300, 25,
                                           hwnd, (HMENU)IDC_LABEL_MAIN, hInst, nullptr);
            SendMessage(hLabelMain, WM_SETFONT, (WPARAM)g_hFontHeading, TRUE);
            // Sub-heading.
            HWND hLabelSub = CreateWindow(_T("STATIC"), _T("Choose a PIN that's 8–20 numbers long."),
                                          WS_CHILD | WS_VISIBLE,
                                          50, 40, 300, 20,
                                          hwnd, (HMENU)IDC_LABEL_SUB, hInst, nullptr);
            SendMessage(hLabelSub, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            // "New PIN" label and edit.
            HWND hLabelNewPin = CreateWindow(_T("STATIC"), _T("New PIN"),
                                             WS_CHILD | WS_VISIBLE,
                                             15, 70, 70, 20,
                                             hwnd, (HMENU)IDC_LABEL_NEWPIN, hInst, nullptr);
            SendMessage(hLabelNewPin, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
            hEditNewPin = CreateWindow(_T("EDIT"), _T(""),
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                                       15, 90, 200, 22,
                                       hwnd, (HMENU)IDC_EDIT_NEWPIN, hInst, nullptr);
            SendMessage(hEditNewPin, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            // "Re-type PIN" label and edit.
            HWND hLabelRePin = CreateWindow(_T("STATIC"), _T("Re-type PIN"),
                                            WS_CHILD | WS_VISIBLE,
                                            15, 125, 70, 20,
                                            hwnd, (HMENU)IDC_LABEL_RETYPE, hInst, nullptr);
            SendMessage(hLabelRePin, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
            hEditRePin = CreateWindow(_T("EDIT"), _T(""),
                                      WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                                      15, 145, 200, 22,
                                      hwnd, (HMENU)IDC_EDIT_RETYPE, hInst, nullptr);
            SendMessage(hEditRePin, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            // "Set PIN" button.
            HWND hButtonOK = CreateWindow(_T("BUTTON"), _T("Set PIN"),
                                          WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                          15, 180, 80, 25,
                                          hwnd, (HMENU)IDC_BUTTON_SETPIN, hInst, nullptr);
            SendMessage(hButtonOK, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            // "Cancel" button.
            HWND hButtonCancel = CreateWindow(_T("BUTTON"), _T("Cancel"),
                                              WS_CHILD | WS_VISIBLE,
                                              110, 180, 80, 25,
                                              hwnd, (HMENU)IDC_BUTTON_CANCEL, hInst, nullptr);
            SendMessage(hButtonCancel, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            LogMessage(L"Window created and controls initialized (with logo).");
            break;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case IDC_BUTTON_SETPIN:
                {
                    const int bufferSize = 256;
                    TCHAR newPinBuf[bufferSize] = { 0 };
                    TCHAR rePinBuf[bufferSize] = { 0 };
                    GetWindowText(hEditNewPin, newPinBuf, bufferSize);
                    GetWindowText(hEditRePin, rePinBuf, bufferSize);

                    std::wstring pin1(newPinBuf);
                    std::wstring pin2(rePinBuf);

                    // Do NOT log the actual PIN.
                    LogMessage(L"Set PIN clicked (PIN entered).");

                    if (pin1.empty() || pin2.empty())
                    {
                        MessageBox(hwnd, _T("Both PIN fields must be filled in."), _T("Input Error"), MB_ICONERROR);
                        LogMessage(L"Error: One or both PIN fields are empty.");
                        return 0;
                    }
                    if (pin1 != pin2)
                    {
                        MessageBox(hwnd, _T("The PINs do not match. Please try again."), _T("Input Error"), MB_ICONERROR);
                        LogMessage(L"Error: PINs do not match.");
                        return 0;
                    }
                    if (!ValidatePIN(pin1))
                    {
                        MessageBox(hwnd, _T("PIN must be numeric and 8–20 digits long."), _T("Input Error"), MB_ICONERROR);
                        LogMessage(L"Error: PIN validation failed.");
                        return 0;
                    }

                    if (SetBitLockerPinWMI(pin1)) {
                        MessageBox(hwnd, _T("BitLocker PIN set successfully."), _T("Success"), MB_ICONINFORMATION);
                        LogMessage(L"BitLocker PIN set successfully.");
                    }
                    else {
                        MessageBox(hwnd, _T("Failed to set BitLocker PIN. Check privileges and BitLocker status."), _T("Error"), MB_ICONERROR);
                        LogMessage(L"Failed to set BitLocker PIN.");
                    }
                    break;
                }
                case IDC_BUTTON_CANCEL:
                {
                    LogMessage(L"Cancel clicked. Exiting application.");
                    PostQuitMessage(0);
                    break;
                }
                default:
                    break;
            }
            break;
        }

        case WM_DESTROY:
        {
            LogMessage(L"Window destroyed. Exiting application.");
            if (g_hFontNormal)
            {
                DeleteObject(g_hFontNormal);
                g_hFontNormal = nullptr;
            }
            if (g_hFontHeading)
            {
                DeleteObject(g_hFontHeading);
                g_hFontHeading = nullptr;
            }
            PostQuitMessage(0);
            break;
        }

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE, LPTSTR, int nCmdShow)
{
    LogMessage(L"Application started.");

    const TCHAR CLASS_NAME[] = _T("BitLockerPINUIClass");
    WNDCLASS wc = {};
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClass(&wc))
    {
        MessageBox(nullptr, _T("Window Registration Failed!"), _T("Error"), MB_ICONERROR);
        LogMessage(L"Error: Window registration failed.");
        return 1;
    }
    LogMessage(L"Window class registered successfully.");

    HWND hwnd = CreateWindow(
        CLASS_NAME,
        _T("BitLocker startup PIN (C:)"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 330, 250,
        nullptr, nullptr, hInstance, nullptr
    );

    if (hwnd == nullptr)
    {
        MessageBox(nullptr, _T("Window Creation Failed!"), _T("Error"), MB_ICONERROR);
        LogMessage(L"Error: Window creation failed.");
        return 1;
    }
    LogMessage(L"Window created successfully.");

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    LogMessage(L"Application exiting.");
    return (int)msg.wParam;
}
