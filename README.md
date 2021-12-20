# Log4j / Log4Shell PowerShell Scan

Based on [Wdrussell1/Log4Shell-Automated](https://github.com/Wdrussell1/Log4Shell-Automated)

Thanks to:
* Datto RMM and Wdrussel for the initial script this was based on
* Florian Roth and Jai Minton for research
* VirusTotal for their excellent tool yara

**Released to Public Domain**

This script is in the public domain and may be used or modified any way you see fit.  We are not responsible for its actions, however efforts have been taken to minimize potential impact. The script makes no overt changes to the system with the exception of installing Visual C++ runtime if needed (this can be disabled).

PULL REQUESTS WELCOME! Bug fixes, performance improvements, function extensions etc are all welcome.

# Functions & Features

* Compatible with Server 2008 and up, 32 or 64-bit *Note, not tested on 32-bit*
* Automatically scans JAR, WAR, EAR, and AAR files for reference to the vunerable package `JndiLookup.class`. Scans those file types plus LOG and TXT files using the [yara](https://github.com/VirusTotal/yara) malware scan tool.
* If yara is unable to run, attempts to detect and if necessary install the Visual C++ Runtime prerequisite. *Note: this can be disabled if undesired*
* Runs a log of all files scanned as well as a PowerShell Transcript log for later review
* Handles failures and errors in a mostly sane manner, attempting to report back if at all possible or at least log the problem in the Transcript.
* Sends an email if any errors with scanning or results are found.
* Optionally sends an email if the scan is successful and NO issues are found.
* If the script terminates with a critical error, is unable to send an email, or is unable to write to the Ninja property (if specified) it will return exit code 1 (error).

The script will include one of several results in the subject of emails and the string returned to Ninja RMM:
* **CLEAN**: Both scans were successful and nothing of concern was found.
* **VULN FOUND**: The scan succeeded. One or more potentially vunerable files was found. No evidence of an attack attempt was identified.' 
* **SCAN-CLEAN YARA-ERROR**: File scan returned clear, however yara was not able to run. Manual intervention may be required.
* **VULN FOUND YARA-ERROR**: File scan identified potentially vunerable files. Yara was not able to run. Manual intervention may be required to review log files.
* **FOUND**: Evidence of one or more Log4Shell attack attempts has been found on the system.
* **ERROR**: An unknown error occurred and the script was not able to run correctly. Please see the Transcript or event log for more detail.

For some result types the email will contain log file contents in the body and attached as a file.

# Notes & Provisos

* File collection gets both JAR files and TXT / log files. This means some unnecessary scanning goes on. For most environments it's not significantly impactful but on very file-dense servers it may be worth filtering that to two blocks of files.
* File collection and filtering is likely non-optimized. PR to improve performance are welcome.
* File scanning for the `JndiLookup.class` string is only applied to .jar, .war, .ear, .aar files. Yara scans all files collected

# Use with RMM tools - Ninja RMM

This script is designed to be distributed with Ninja RMM and report back to a custom environment variable as well as sending an email. However it will work fine when executed directly and can be easily modified to work with most other RMM tools.

## Ninja
Specific to Ninja there is a Parameter called `NinjaProperty` that is used to set the name of the property you want to report back to.

## Other RMM tools
If you're using another RMM tool you'll want to fork the main script or just get results by email. The script fails sanely, you won't get a stopping error due to the Ninja functionality. If you fork or download the main script, look for this code block:

```PowerShell
    if ($NinjaProperty) {
        try { Ninja-Property-Set log4jDetection $ninjaString }
        catch { Write-Host 'Unable to set Ninja Property' -ForegroundColor Red; $_exitCode = 1 }
    }
```

The easiest solution for something like Kaseya that just reads *RETURN* values is to have the script `return $ninjaString`.  `$ninjaString` is a single-line property that contains a datestamp and appropriate result code.

# How to use

**NOTE ON SECURITY** As either of these methods include potentially placing email credentials in a log file accessible to users on the system it is reccomended you utilize a temporary email address on your server and / or clear the script after it is run. This script does *NOT* attempt any type of cleanup on its own.

## Automatically pull script

1. Download `Log4jScanner-Runner.ps1`
2. Modify parameter list within
3. Execute on target system(s)

## Download script and run with parameters

1. Download `Log4jScanner.ps1`
2. Distribute and run how you see fit, using PowerShell parameters at run-time. **This is the most secure way to execute the script as credentials are not stored on the file system**

## Fork or download script and modify

1. For the repo or download `Log4jScanner.ps1`
2. Modify script as it best fits your needs. This can be as simple as changing hardcoded parameter values or as complex as a full rewrite. Go ham!

# Parameters and how they're used

These parameters exist in both the main script and the runner and may be modified in either location.

| Parameter Name | Default | Description |
| ---------------|---------|------------ |
| ScanScope      | 2       | 1: Scan files on Home Drive (usually C:)<br>2: Scan files on fixed and removable drives<br>3: Scan files on all detected drives, even network drives
| Root           | C:\temp\log4j | Root location for downloaded files and logs. Do not include trailing backslash.
| LogTo          | `$Root\logs` | Path for log files
| InstallVCCIfneeded | `$true` | If Visual C++ is missing yara will not be able to run. The script will attempt to install it if necessary.
| FilterSyncRootsFromUserProfile | `$true` | Filters user profile paths to only scan specific folders: \AppData, \Documents, \Desktop, \Pictures, \Downloads. This prevents things like OneDrive and Dropbox from downloading files "on-demand" as the scanner runs.
| ExcludedPaths | ```$Root``` <br> C:\$RECYCLE.BIN\ <br> C:\ProgramData\NinjaRMMAgent| Exclude specific paths. Allows wildcarding (E.g. C:\Users\*\FolderEveryUserHas).  Do NOT include trailing backslash and asterisk wildcard character. If you specify this parameter please include the default values or expect those areas to be scanned.
| NinjaProperty | *NONE* | Property name to report back to for Ninja RMM. Do not specify if you are not running this with Ninja RMM or if you don't want to use this functionality.
| MailSMTPServer | mail.smtp2go.com | SMTP server name for email
| MailPort | 2525 | SMTP server port
| MailUseSSL | `$true` | Use SSL when connecting to SMTP server
| MailServerCredential | *NONE* | Credential object to use when authenticating to the mail server (Basic Auth). Alternately you may specify username and password as strings below.
| MailServerUsername | *NONE* | Mail server authentication username. Ignored if -MailServerCredential is specified
| MailServerPasswordPlaintext | *NONE* | Mail server authentication password. Ignored if -MailServerCredential is specified
| MailFrom | *NONE-MANDATORY* | Envelope-from value
| MailTo | *NONE-MANDATORY* | Envelope-to Value
| SendOnSuccess | `$false` | Send an email even if the system comes back clean with no problems scanning. Will be 1:1 email per system.
