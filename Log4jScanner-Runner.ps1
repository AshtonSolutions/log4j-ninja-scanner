<##################################### LOG4J / LOG4SHELL SCRIPT RUNNER #######################################
This script downloades the latest version of https://github.com/AshtonSolutions/log4j-ninja-scanner and
executes it with provided parameters. Using this script makes it easier to keep up with changes if you are
deploying this via an RMM tool such as Ninja, Datto, Kaseya.

See repo readme for details on script and how to utilize it.

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

# Download the latest version of the script
$rawScriptUri     = 'https://raw.githubusercontent.com/AshtonSolutions/log4j-ninja-scanner/main/Log4JScanner.ps1'
$downloadFolder   = $env:temp
$downloadFileName = 'Log4JScanner.ps1'
$downloadPath =  "$downloadFolder\$downloadFileName"

# Delete script if it already exists
if (Test-Path -Path $downloadPath -PathType Leaf) {
    Remove-Item -Path $downloadPath -Force
    Write-Host "$downloadPath already exists, deleted." -ForegroundColor Cyan
}

# Downloading the file with error catching
try {
    Invoke-WebRequest -Method Get -Uri $rawScriptUri -OutFile $downloadPath # Downloads the script
}
catch {
    Write-Error "Failed to download script from $rawScriptUri to $downloadPath"
    exit 1 # Exit if errors
}

Write-Host "Downloaded script from " -NoNewline
Write-Host $rawScriptUri -Foreground DarkYellow -NoNewline
Write-Host " to " -NoNewline
Write-Host $downloadPath -Foreground DarkCyan

# Finally, run the script
Write-Host "Attempting to execute $downloadPath"
# Re-splat the parameters
Invoke-Expression -Command "$downloadPath @PSBoundParameters" 
