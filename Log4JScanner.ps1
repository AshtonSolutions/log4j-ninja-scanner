<##################################### LOG4J / LOG4SHELL SCANNING SCRIPT #######################################
This script scans for evidence of an application with the Log4j Vulnerability (CVE-2021-44228), and for evidence
an attack was made against the system targeting this vunerability.

Based on https://github.com/Wdrussell1/Log4Shell-Automated which itself is based on a script from Datto RMM.

Author: Adam Burley
Company: Ashton Technology Solutions (https://ashtonsolutions.com) ///talked.plan.honest
Copyright: This script is released into PUBLIC DOMAIN.  We're all in this together.
#################################################################################################################>
[CmdletBinding()]
param (
    # Scan Scope
    #   1: Scan files on Home Drive (usually C:)
    #   2: Scan files on fixed and removable drives
    #   3: Scan files on all detected drives, even network drives
    [int]$ScanScope = 2,

    # Root path for files to be downloaded to. No trailing backslash, please
    [string]$Root = "C:\temp\log4j",

    # Path for log files. No trailing backslash, please
    [string]$LogTo = "$Root\logs",

    # If yara test fails, check for and install Visual C++ if needed.
    [bool]$InstallVCCIfneeded = $true,

    # Filters user profile paths to only scan specific folders: \AppData, \Documents, \Desktop, \Pictures, \Downloads.
    # This prevents things like OneDrive and Dropbox from force-downloading files.
    $FilterSyncRootsFromUserProfile = $true,

    # Exclude specific paths. Allows wildcarding (E.g. C:\Users\*\FolderEveryUserHas).
    # Do NOT include trailing backslash and asterisk wildcard character.
    # The default value is to exclude the Root folder path, Recycle Bin folder, and Ninja's ProgramData path.
    # If you specify this parameter please re-include those values or expect those areas to be scanned.
    [string[]]$ExcludedPaths,

    # Property name to report back to for Ninja RMM. Do not specify if you are not running this with Ninja RMM or if you don't want to use this functionality.
    [string]$NinjaProperty,

    ## ----- MAIL SETTINGS ----- ##

    # SMTP server name for email
    [string] $MailSMTPServer = 'mail.smtp2go.com',

    # SMTP server port
    [int] $MailPort = 2525,

    # Use SSL / TLS on mail server
    [bool] $MailUseSSL = $true,

    # Credential object to use when authenticating to the mail server (Basic Auth)
    [System.Management.Automation.PSCredential] $MailServerCredential,

    # Mail server authentication username. Ignored if -MailServerCredential is specified
    [string]$MailServerUsername,

    # Mail server authentication password. Ignored if -MailServerCredential is specified
    [string]$MailServerPasswordPlaintext,

    # Envelope-from value. If you hard-code this value, set Mandatory=$false
    [Parameter(Mandatory=$true)]
    [string]$MailFrom,

    # Envelope-to value. If you hard-code this value, set Mandatory=$false
    [Parameter(Mandatory=$true)]
    [string]$MailTo,

    # Send an email even if the system comes back clean with no problems scanning. Will be 1:1 email per system.
    $SendOnSuccess = $false
)
#region ------------------ PARAMETER SETUP ------------------
if (-not $ExcludedPaths) {
    $ExcludedPaths = @( # Paths explicitly to exclude from scanning. See parameter comment for more information.
        $root
        'C:\$RECYCLE.BIN'
        'C:\ProgramData\NinjaRMMAgent'
    )
}
if (-not $MailServerCredential) { $MailServerCredential = [System.Management.Automation.PSCredential]::new($MailServerUsername,(ConvertTo-SecureString -String $MailServerPasswordPlaintext -AsPlainText -Force))  }
# E-mail setup
$mail = @{
    SMTPServer = $MailSMTPServer
    Port = $MailPort
    UseSSL = $MailUseSSL
    # Replace username and password, or comment line out if not using authentication.
    Credential = $MailServerCredential
    From = $MailFrom
    To = $MailTo
}

# STATIC VARIABLES - You probably don't need to change them.

$VERSION = '1220-1454-public'
[string]$arch=[intPtr]::Size*8 # 32 or 64 bit OS

# Yara files - as of 12/17/21 4.1.3 is the current version but here's where you change the URL if needed.
$YARA_32_URI = 'https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-v4.1.3-1755-win32.zip'
$YARA_64_URI = 'https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-v4.1.3-1755-win64.zip'

$fileDate = Get-Date -F 'yyyy-MM-dd HH-mm-ss' # Date string format for files

$TRANSCRIPT_PATH = "$LogTo\$fileDate Run Transcript.txt"
$DETECTIONFILE_PATH = "$LogTo\$fileDate L4jDetections.txt"
#endregion
#region ------------------- SETUP & FUNCTIONS -------------------


# Create our output folders if not present
New-Item -ItemType Directory -Force -Path $Root | Out-Null
New-Item -ItemType Directory -Force -Path $LogTo | Out-Null

# Move to the root location
Set-Location $Root
# Delete everything but the folders e.g. log folder.
Remove-Item $Root\*.*

Start-Transcript -Path $TRANSCRIPT_PATH -Force

Write-Host "Log4j/Log4Shell CVE-2021-44228 Scanning/Mitigation Tool (seagull/Datto/Ashton)" -ForegroundColor Cyan
Write-Host "=======================================================================" -ForegroundColor Cyan
Write-Host "Detections from this run will be logged to $DETECTIONFILE_PATH" -ForegroundColor DarkYellow
Write-Host "Script Version: $version"  -ForegroundColor DarkYellow
Write-Host "Current Path: " (Get-Location | Select-Object -ExpandProperty Path) -ForegroundColor DarkYellow
Write-Host "Parameters for this run:" -ForegroundColor Yellow
Write-Host "`tScanScope: $ScanScope"
Write-Host "`tRoot: $Root"
Write-Host "`tLogTo: $LogTo"
Write-Host "`tInstallVCCIfneeded: $InstallVCCIfneeded"
Write-Host "`tFilterSyncRootsFromUserProfile: $FilterSyncRootsFromUserProfile"
Write-Host "`tExcludedPaths: " ($ExcludedPaths | Out-String)
Write-Host "`tNinjaProperty": $NinjaProperty
Write-Host "`tMailSMTPServer: $MailSMTPServer"
Write-Host "`tMailPort: $MailPort"
Write-Host "`tMailUseSSL: $MailUseSSL"
Write-Host "Mail credential information skipped for security reasons."
Write-host "`tMailFrom: $MailFrom"
Write-Host "`tMailTo: $MailTo"
Write-Host "`tSendOnSuccess: $SendOnSuccess"

# Force TLS 1.2 for downloading files
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

<#
0: Success, No problems found
1: Success, Potentially vunerable files found
2: General error, not caught. the default error
3: File scan came back clean but yara was unable to run
4: File scan found potentially vunerable files, yara was unable to run
5: Success, yara identified attacks in log files
#>
$ResultCode = 0

function Send-Result {
    $_serverName = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty 'Name'
    $_serverDomain = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty 'Domain'
    $_bodyBase = "NAME: $_serverName`nDOMAIN: $_serverDomain`n`n"
    $_exitCode = 0
    if ($ResultCode -eq 0) { # Success, No problems found
            Write-Host '- There is no indication that this system has received Log4Shell attack attempts.' -ForegroundColor Green
            $mail.Subject = "Log4j CLEAN: $_serverDomain\$_serverName"
            $mail.Body = $_bodyBase + "This system has been scanned for potentially vunerable files and evidence of attack. " +
                        "There is no indication the system is vunerable or under attack.`nScan Version: $version"
            $ninjaString = "$((Get-Date).ToString()) CLEAN"
    } elseif ($ResultCode -eq 1) { # Success, Potentially vunerable files found
            $_message = '! The scan succeeded. One or more potentially vunerable files was found. No evidence of an attack attempt was identified.' 
            Write-Host $_message -ForegroundColor Blue
            $mail.Subject = "Log4j VULN FOUND: $_serverDomain\$_serverName"
            $mail.Body = $_bodyBase + "$_message`nSee below log data for more information. Scan Version: $version`n`n" + (Get-Content $DETECTIONFILE_PATH)
            $mail.Attachments = $DETECTIONFILE_PATH
            $ninjaString = "$((Get-Date).ToString()) VULN FOUND"
    } elseif ($ResultCode -eq 3) { # File scan came back clean but yara was unable to run
            $_message = '! file scan returned clear, however yara was not able to run. Manual intervention required to review log files.'
            Write-Host $_message -ForegroundColor DarkRed
            $mail.Subject = "Log4j SCAN-CLEAN YARA-ERROR: $_serverDomain\$_serverName"
            $mail.Body = $_bodyBase + "$_message`nScript run transcript is below. Scan Version: $version`n`n" + (Get-Content $TRANSCRIPT_PATH)
            $ninjaString = "$((Get-Date).ToString()) SCAN-CLEAN YARA-ERROR"
    } elseif ($ResultCode -eq 4) { # File scan found potentially vunerable files, yara was unable to run
            $_message = '! File scan identified potentially vunerable files. Yara was not able to run. Manual intervention may be required to review log files.'
            Write-Host $_message -ForegroundColor DarkRed
            $mail.Subject = "Log4j VULN FOUND YARA-ERROR: $_serverDomain\$_serverName"
            $mail.Body = $_bodyBase + "$_message`nSee below log data for more information. Scan Version: $version`n`n" + (Get-Content $DETECTIONFILE_PATH)
            $mail.Attachments = $DETECTIONFILE_PATH
            $mail.Priority = [System.Net.Mail.MailPriority]::High
            $ninjaString = "$((Get-Date).ToString()) VULN FOUND YARA-ERROR"
    } elseif ($ResultCode -eq 5) { # Success, yara identified attacks in log files
            $_message = '! Evidence of one or more Log4Shell attack attempts has been found on the system.'
            Write-Host $_message -ForegroundColor Red
            $mail.Subject = "Log4j FOUND: $_serverDomain\$_serverName"
            $mail.Body = $_bodyBase + "$_message`nReview the logfile below (copy also attached to email). Scan Version: $version`n`n" + (Get-Content $DETECTIONFILE_PATH)
            $mail.Attachments = $DETECTIONFILE_PATH
            $mail.Priority = [System.Net.Mail.MailPriority]::High
            $ninjaString = "$((Get-Date).ToString()) FOUND"
    } else { # General error, not caught. the default error. Explicitly set as 2
            $_message = 'An unknown error occurred and the script was not able to run correctly. Please see the Transcript or event log for more detail.'
            Write-Host $_message -ForegroundColor Red
            $mail.Subject = "Log4j ERROR: $_serverDomain\$_serverName"
            $mail.Body = $_bodyBase + $_message + "`n`n"
            foreach ($e in $Error){ # Append all $Error values to the email body
                $mail.Body += "`n-----------------------------------------------------------`n"
                $mail.Body += ($e | Select-Object -Property * | Format-List | Out-String).trim()
            }
            $mail.Priority = [System.Net.Mail.MailPriority]::High
            $ninjaString = "$((Get-Date).ToString()) ERROR"
            $_exitCode = 1
    }
    if ($ResultCode -ne 0 -or $SendOnSuccess) {
        try { Send-MailMessage @mail } # Send email
        catch { $_exitCode = 1; $ninjaString = "$((Get-Date).ToString()) SENDERROR"; Write-host 'Unable to send email' -ForegroundColor Red }
    }

    # Return data to RMM tool
    if ($NinjaProperty) {
        try { Ninja-Property-Set log4jDetection $ninjaString }
        catch { Write-Host 'Unable to set Ninja Property' -ForegroundColor Red; $_exitCode = 1 }
    } else { Write-Host 'Ninja property not specified.' -ForegroundColor DarkBlue }

    Stop-Transcript
    exit $_exitCode
}

#endregion
#region --------------------- YARA SETUP ---------------------

# Retrieve yara and a default set of scanning conditions
Invoke-WebRequest -Uri $YARA_32_URI -OutFile $Root\yara32.zip
Invoke-WebRequest -Uri $YARA_64_URI -OutFile $Root\yara64.zip
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/expl_log4j_cve_2021_44228.yar' -OutFile "$Root\expl_log4j_cve_2021_44228.yar"
# Expand-Archive requires PowerShell 5.0.  To maintain compatibility with PS 3 for Server 2008+ we'll use a .net method instead.
# https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile.extracttodirectory?view=netcore-3.1
Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
[IO.Compression.ZipFile]::ExtractToDirectory("$Root\yara32.zip", $Root)
[IO.Compression.ZipFile]::ExtractToDirectory("$Root\yara64.zip", $Root)

# Update yara rules
$varYaraNew = (New-Object System.Net.WebClient).DownloadString('https://github.com/Neo23x0/signature-base/raw/master/yara/expl_log4j_cve_2021_44228.yar')
if ($varYaraNew -match 'TomcatBypass') {
    Set-Content -Value $varYaraNew -Path $Root\yara.yar -Force
    Write-Host "- New YARA definitions downloaded." -ForegroundColor Yellow
} else {
    Write-Host "! ERROR: New YARA definition download failed." -DarkRed
    Write-Host "  Falling back to built-in definitions." -ForegroundColor DarkRed
    Copy-Item -Path "$Root\expl_log4j_cve_2021_44228.yar" -Destination "$Root\yara.yar" -Force
}

# Test 
if (-not (Test-Path -Path "$Root\yara$arch.exe" -PathType Leaf)) {
    Write-Host "! ERROR: yara$arch.exe not found. Possibly download failed." -ForegroundColor Red
    Write-Host "Script will continue to scan files only."
    $ResultCode = 3
} else {
    Write-Host "- Verified presence of yara$arch.exe. Verifying yara will run..." -ForegroundColor Yellow
    cmd /c "$Root\yara$arch.exe -v >nul 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "! ERROR: YARA was unable to run on this device." -ForegroundColor Red
        # https://yara-ctypes.readthedocs.io/en/latest/howto/install.html#missing-a-dll-try-installing-ms-vc-2010-redistributable-package
        # Found in testing it needs VCRUNTIME140.dll which is VS 2015 or newer
        Write-Host "Visual C++ 2015 or greater runtime is required for yara to execute. The following runtimes 2015+ are installed:" -ForegroundColor Cyan
        $runtimes = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Visual C++ 201%'" | Where-Object {
            $_.Name -ilike "*2015*" -or $_.Name -ilike "*2017*" -or $_.Name -ilike "*2019*" -or $_.Name -ilike "*2022*"
        }
        $runtimes | Select-Object -ExpandProperty Name
        if ($runtimes) {
            Write-Host 'Compatible runtime found but yara still failed. Abandoning yara attempt.' -ForegroundColor Red
            Write-Host "! ERROR: YARA was unable to run on this device." -ForegroundColor Red
            Write-Host "Script will continue to scan files only."
            $ResultCode = 3
        } elseif ($InstallVCCIfneeded) { # Try to install Visual C++ Runtime
            Write-Host "Compatible VC++ runtime not found. Attempting to install Visual C++ 2022" -ForegroundColor Cyan
            $uri = if ($arch -eq '32') { 'https://aka.ms/vs/17/release/VC_redist.x86.exe' } else { 'https://aka.ms/vs/17/release/VC_redist.x64.exe' }
            Invoke-WebRequest -Uri $uri -OutFile "$Root\VC_redist.x$arch.exe"
            if (-not (Test-path -Path $Root\VC_redist.x$arch.exe)) {
                Write-host 'VC installer not found. Something possibly wrong with download. Abandoning install attempt'
                Write-Host "! ERROR: YARA was unable to run on this device." -ForegroundColor Red
                Write-Host "Script will continue to scan files only."
                $ResultCode = 3
            } else {
                Start-Process -FilePath $Root\VC_redist.x$arch.exe -ArgumentList "/install","/quiet","/norestart" -Wait
                Write-Host 'Retesting yara'
                cmd /c "$Root\yara$arch.exe -v >nul 2>&1"
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "! ERROR: YARA was unable to run on this device." -ForegroundColor Red
                    Write-Host "Script will continue to scan files only."
                    $ResultCode = 3
                } else {
                    Write-Host "yara test run succeeded" -ForegroundColor Cyan
                }
            }
        } else { 'YARA was not able to run. Please install Visual C++ Runtime 2015 or newer and retry or troubleshoot based on log files. Script will run scan files only.'; $ResultCode = 3 }
    } else {
        Write-Host "yara test run succeeded" -ForegroundColor Cyan
    }
}
#endregion
#region ------------------------ EXECUTION: FILE COLLECTION ---------------------------
#map input variable ScanScope to an actual value
switch ($ScanScope) {
    1   {
        Write-Host "- Scan scope: Home Drive"
        $ScanDrives = @($env:HomeDrive)
    } 2 {
        Write-Host "- Scan scope: Fixed & Removable Drives"
        $ScanDrives = Get-WmiObject -Class Win32_logicaldisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 3 } | Where-Object { $_.FreeSpace } | Foreach-Object { $_.DeviceID }
    } 3 {
        Write-Host "- Scan scope: All drives, including Network"
        $ScanDrives = Get-WmiObject -Class Win32_logicaldisk | Where-Object { $_.FreeSpace } | Foreach-Object { $_.DeviceID }
    } default {
        Write-Host "! ERROR: Unable to map scan scope variable to a value. (This should never happen!)"
        $ResultCode = 2
        Send-Result # Exit here
    }
}

#start a logfile
Write-Host "`r`nPlease expect some permissions errors as some locations are forbidden from traversal.`r`n=====================================================`r`n" -ForegroundColor Magenta
Add-content -Path $DETECTIONFILE_PATH -Value "Files scanned:"
Add-Content -path $DETECTIONFILE_PATH -Value "====================================================="
Add-Content $DETECTIONFILE_PATH -Value " :: Scan Started: $(get-date) ::"


#get a list of all files-of-interest on the device (depending on scope) :: GCI is broken; permissions errors when traversing root dirs cause aborts (!!!)
Write-Host (Get-Date -f 'MM/dd HH:mm:ss') "File scan start"
$arrFiles = [System.Collections.ArrayList]@()
foreach ($drive in $ScanDrives) {
    Get-ChildItem "$drive\" -force | Where-Object {$_.PSIsContainer} | Foreach-Object {
            Get-ChildItem -path "$drive\$_\" -rec -force -include *.jar,*.war,*.ear,*.aar,*.log,*.txt -ErrorAction 0 | Foreach-Object {
            $arrFiles.Add($_.FullName) | Out-Null
        }
    }
}
Write-Host (Get-Date -f 'MM/dd HH:mm:ss') $arrFiles.Count " total files."

# Filter under user path to only include AppData, Documents, Downloads, Desktop, Pictures. This prevents issues with syncing applications (OneDrive, SharePoint, Dropbox, etc) downloading files on-demand.
if ($FilterSyncRootsFromUserProfile) {
    $arrFiles = $arrFiles | Where-Object {
        $_ -inotlike "C:\Users\*" -or
        $_ -ilike "C:\Users\*\AppData*" -or
        $_ -ilike "C:\Users\*\Desktop*" -or
        $_ -ilike "C:\Users\*\Documents*" -or
        $_ -ilike "C:\Users\*\Pictures*" -or
        $_ -ilike "C:\Users\*\Downloads*"
    }
    Write-Host (Get-Date -f 'MM/dd HH:mm:ss') $arrFiles.Count " files after trimming User data."
}

# Remove excluded paths
foreach ($exclusion in $ExcludedPaths) {
    $arrFiles = $arrFiles | Where-Object { $_ -inotlike "$exclusion\*" }
}
Write-Host (Get-Date -f 'MM/dd HH:mm:ss') $arrFiles.Count " files after trimming Excluded path data."

#endregion
#region ------------------------ EXECUTION: SCAN JARS ---------------------------
#scan i: JARs containing vulnerable Log4j code
write-host "====================================================="
write-host (Get-Date -f 'MM/dd HH:mm:ss') "- Scanning for JAR files containing potentially insecure Log4j code..."
$fileScanLog = "$LogTo\$fileDate File Scan Log.txt"
$arrFiles | Where-Object {$_ -match '\.jar$|\.war$|\.ear$|\.aar$'} | Foreach-Object {
    try {
        Add-Content -Path $fileScanLog -Value $file -ErrorAction Stop
    } catch {
        Start-Sleep -Seconds 1
        Add-Content -Path $fileScanLog -Value $file -ErrorAction SilentlyContinue
    }
    if (Select-String -Quiet -Path $_ "JndiLookup.class") {
        Write-Host (Get-Date -f 'MM/dd HH:mm:ss') "! ALERT: Potentially vulnerable file at $($_)!" -ForegroundColor Red
        Add-Content -Path $DETECTIONFILE_PATH -Value "! CAUTION !`r`n$(get-date)"
        Add-Content -Path $DETECTIONFILE_PATH -Value "POTENTIALLY VULNERABLE JAR: $($_)"
        $ResultCode++ # 0, no problems > 1, potential problems found or 3, yara error > 4, yara error and potentially vunerable files found
    }
}

if ($ResultCode -in (3,4)) {
    Write-Host "yara was not able to run on system. Abandoning scan and sending existing results." -ForegroundColor Red
    Send-Result
}
#endregion
#region --------------------- EXECUTION: YARA -----------------------------
Write-Host "=====================================================" -ForegroundColor Magenta
Write-Host "- Scanning LOGs, TXTs and JARs for common attack strings via YARA scan......" -ForegroundColor Magenta
$yaraScanLog = "$LogTo\$fileDate Yara Scan Log.txt"
foreach ($file in $arrFiles) {
    #add it to the logfile, with a pause for handling
    try {
        Add-Content -Path $yaraScanLog -Value $file -ErrorAction Stop
    } catch {
        Start-Sleep -Seconds 1
        Add-Content -Path $yaraScanLog -Value $file -ErrorAction SilentlyContinue
    }

    #scan it
    Clear-Variable -Name yaResult -ErrorAction SilentlyContinue
    try {
        $yaResult = cmd /c "$Root\yara$arch.exe `"yara.yar`" `"$file`" -s" # Executes yara and waits for it to return
        if ($yaResult) {
            Write-Host "=====================================================" -ForegroundColor Red
            Write-Host "! DETECTION:" -ForegroundColor Red
            Write-Host $yaResult -ForegroundColor Cyan
            Add-Content -Path $DETECTIONFILE_PATH -Value "! INFECTION DETECTION !`r`n$(get-date)"}
            Add-Content -Path $DETECTIONFILE_PATH -Value $yaResult
            $ResultCode = 5
        }
    catch { 
        Write-Host "Error: " $_.toString() -ForegroundColor DarkRed 
        Add-Content -Path $DETECTIONFILE_PATH -Value "----------------------------------------------------`nError scanning $file with yara. Check Transcript log`n---------------------------------------"
    }
}
#endregion
Add-Content -Path $DETECTIONFILE_PATH -Value " :: Scan Finished: $(get-date) ::"
Send-Result