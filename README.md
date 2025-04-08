BitLocker PIN UI
A production-ready Win32 application for setting the BitLocker startup PIN on drive C:. This tool uses WMI to call BitLocker management APIs, provides robust input validation, and offers a modern-looking user interface with logging capabilities.

Important:

Administrator Privileges are Required. Ensure that you run this application with elevated privileges (or as SYSTEM) so that WMI operations succeed.

Common Controls v6 Manifest: To achieve modern theming (Segoe UI, etc.), include a manifest that enforces dependency on version 6 of the common controls.

TPM + PIN: The application is designed to add a TPM+PIN protector. Verify that your system has BitLocker enabled with a compatible TPM configuration.

Features
Modern User Interface:

Uses the Segoe UI font.

Displays a custom icon (logo) at the top-left corner.

Clean layout with headings, subheadings, and labeled PIN fields.

Robust Input Validation:

Validates that both PIN fields are filled.

Ensures that the new PIN and re-type PIN match.

Confirms that the PIN is numeric and between 8 and 20 digits.

BitLocker Configuration via WMI:

Calls the WMI AddKeyProtector method to apply the TPM + PIN protector for drive C:.

Handles WMI calls with proper error checking and cleans up COM resources.

Security Best Practices:

The application never logs the actual PIN value (only that a PIN was entered).

Logs key events and errors to an absolute file path (e.g., C:\Temp\BitLockerPINUI.log).

Robust Error Handling and Logging:

Errors are displayed to the user via MessageBox.

A log file is generated with timestamps to record major events and errors.

Prerequisites
Windows Operating System:
The application is built using the Win32 API and requires Windows.

BitLocker Enabled:
Ensure that BitLocker is activated on drive C: and that your system is configured for TPM+PIN protection if applicable.

Administrator Rights:
The application must run as an administrator (or under the SYSTEM account) for WMI calls to succeed.

Common Controls v6 Manifest:
To enable modern theming, include a manifest in your project with the following dependency:

xml
Copier
<dependency>
    <dependentAssembly>
        <assemblyIdentity
          type="win32"
          name="Microsoft.Windows.Common-Controls"
          version="6.0.0.0"
          processorArchitecture="*"
          publicKeyToken="6595b64144ccf1df"
          language="*"/>
    </dependentAssembly>
</dependency>
See Microsoft's documentation for more details.

Installation
Clone the Repository:

bash
Copier
git clone https://github.com/yourusername/BitLockerPINUI.git
cd BitLockerPINUI
Resource Setup:
Ensure the following files are present:

resource.h (defines IDI_BITLOCKERICON)

app.rc (includes the icon resource, e.g., IDI_BITLOCKERICON ICON "BitLockerIcon.ico")

Place your icon file (e.g., BitLockerIcon.ico) in the same directory or update the resource script path accordingly.

Build the Application:
Open the project in Visual Studio:

Make sure to include your manifest in the project for Common Controls v6.

Build the project in your desired configuration (Debug/Release).

Set Up Log Directory:
The application writes logs to C:\Temp\BitLockerPINUI.log. Ensure that the directory exists and that your account has write permissions. You can also modify the log path in the source code if needed.

Usage
Run the Application:
Right-click the executable and select Run as Administrator.
Alternatively, use an elevated command prompt:

bash
Copier
BitLockerPINUI.exe
Set the PIN:

The UI displays a heading, subheading, and two input fields for the new PIN and for re-typing it.

Enter a new PIN that is numeric and between 8 and 20 digits long.

Click the Set PIN button to attempt to apply the new BitLocker startup PIN.

Feedback:

If successful, a success message is displayed.

If there is an error (such as invalid input or failure in WMI call), an error message is shown.

Troubleshooting
Failed to Set BitLocker PIN:

Check your BitLocker configuration on drive C:.

Ensure your system supports TPM+PIN and that BitLocker is enabled.

Verify you are running the application with administrator privileges.

Review the log file (C:\Temp\BitLockerPINUI.log) for error details.

Resource/Manifest Issues:

If the modern theming is not applied, confirm your manifest file includes the Common Controls v6 dependency.

Use tools like Resource Hacker to inspect the embedded resources if needed.

License
This project is licensed under the MIT License.

Contributing
Contributions are welcome! Please feel free to open issues or submit pull requests if you have suggestions or improvements.

Disclaimer
This tool is intended for demonstration and administrative purposes. Use it at your own risk. Ensure you test in a controlled environment before deploying in production.
