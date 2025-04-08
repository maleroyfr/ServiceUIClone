# BitLocker PIN UI & ServiceUIClone

## 🔐 BitLockerPINUI

A user-friendly Win32 application that securely prompts for and sets a BitLocker TPM+PIN protector on the system drive (`C:`) using the Windows Management Instrumentation (WMI) API.

### ✅ Features
- **Modern UI** (Segoe UI, Common Controls v6)
- **Secure PIN handling**: PIN is never logged or displayed.
- **Robust input validation** (numeric, 8–20 digits, match check)
- **Direct WMI integration** for BitLocker configuration
- **Informative logging** to `C:\Temp\BitLockerPINUI.log`
- **Custom icon/logo** support via resource file

### ⚙️ Requirements
- **Windows with BitLocker + TPM support**
- **Run as Administrator**
- `C:\Temp` must exist (or modify log path in `LogMessage`)
- Visual Studio (tested with 2019/2022) for building

### 🔧 Setup
1. Place an icon in the project directory (e.g. `BitLockerIcon.ico`)
2. Add the following to your resource files:
   **`resource.h`**
   ```cpp
   #pragma once
   #define IDI_BITLOCKERICON 2000

A minimal yet powerful clone of Microsoft.ServiceUI.exe used in SCCM and MDT to launch UI applications from a SYSTEM context into the currently logged-in user's session.

✅ Features
Launches any process (e.g. UI apps) in the active user session

Uses WTSQueryUserToken + CreateProcessAsUser

Logs to C:\Temp\ServiceUIClone.log

Designed for use in SYSTEM contexts (e.g. Task Scheduler, services)

📦 Usage
bash
Copier
Modifier
ServiceUIClone.exe "notepad.exe"
⚙️ Requirements
Must be run as Administrator (or SYSTEM)

Built as a Win32 Console App

Link against wtsapi32.lib

Ensure C:\Temp exists for logging

🔧 Build Notes
Use Visual Studio with wtsapi32.lib linked

You can hardcode or pass the command-line argument dynamically