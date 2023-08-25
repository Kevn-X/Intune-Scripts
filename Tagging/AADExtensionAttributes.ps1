# Functions
Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
 
.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.
 
.EXAMPLE
Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret
 
-#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$Tenant,
        [Parameter(Mandatory = $false)] [string]$AppId,
        [Parameter(Mandatory = $false)] [string]$AppSecret,
        [Parameter(Mandatory = $false)] [string]$scopes
    )

    Process {
        Import-Module Microsoft.Graph.Authentication
        $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

        if ($AppId -ne "") {
            $body = @{
                grant_type    = "client_credentials";
                client_id     = $AppId;
                client_secret = $AppSecret;
                scope         = "https://graph.microsoft.com/.default";
            }
     
            $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
            $accessToken = $response.access_token
     
            #$accessToken
            if ($version -eq 2) {
                write-host "Version 2 Module Detected" -ForegroundColor Green
                Write-Output "Version 2 Module Detected (microsoft.graph.authentication)" | Out-File -FilePath "$LogPath$Logname" -Append
                $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                write-host "Version 1 Module Detected" -ForegroundColor Green
                Write-Output "Version 1 Module Detected (microsoft.graph.authentication)" | Out-File -FilePath "$LogPath$Logname" -Append
                Select-MgProfile -Name Beta
                $accesstokenfinal = $accessToken
            }
            $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)" -ForegroundColor Green
            Write-Output "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)" | Out-File -FilePath "$LogPath$Logname" -Append
        }
        else {
            if ($version -eq 2) {
                write-host "Version 2 Module Detected"
                Write-Output "Version 2 Module Detected (microsoft.graph.authentication)" | Out-File -FilePath "$LogPath$Logname" -Append
            }
            else {
                write-host "Version 1 Module Detected"
                Write-Output "Version 1 Module Detected (microsoft.graph.authentication)" | Out-File -FilePath "$LogPath$Logname" -Append
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -scopes $scopes
            Write-Host "Connected to Intune tenant $($graph.TenantId)" -ForegroundColor Green
            Write-Output "Connected to Intune tenant $($graph.TenantId)" | Out-File -FilePath "$LogPath$Logname" -Append
        }
    }
}    


Function Update-Property{
    <#
.SYNOPSIS
Posts extension attributes to the EntraID Device that are specified.
 
.DESCRIPTION
The Update-Property cmdlet is a wrapper cmdlet that helps post extension attributes to EntraID devices via the Graph Api.
 
.EXAMPLE
Update-Property -Attribute 'extensionAttribute5 -Value $business
 
-#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Attribute,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Value
    )
    
    $String1 = '{ "extensionAttributes": { '
    $String2 = ':'
    $String3 = ' } }'
    $Device = $String1 + '"' + $Attribute + '"' + $String2 + ' "' + $Value + '"' + $String3
    Update-MgDevice -DeviceId $deviceId -BodyParameter $Device
    Write-Output "$Attribute : $Value" | Out-File -FilePath "$LogPath$Logname" -Append
}



# Setting the stage
# ... Install Modules
$requiredModules = @(
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue)) {
        Install-Module $module -Force
        Import-Module $module -Force
        Write-Host "Installed and imported module $module" -ForegroundColor Green
    } else {
        Write-Host "Module $module is already installed" -ForegroundColor Green
    }
}

# ... Establish Logging
$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\"
$Logname = "AAD-Tagging.log"
$Date = Get-Date -Format "MM-dd-yyyy hh:mm tt"

if (-not (Test-Path "$LogPath$Logname")) {
    New-Item -Path $LogPath -Name $Logname | Out-Null
    Write-Host "Log File created." -ForegroundColor Green
}

$loggingInfo = @(
    "Script Start Time: $Date",
    "Computer Name: $env:COMPUTERNAME",
    "Logged In UserName: $($env:USERNAME)",
    "Ran By: $(whoami)",
    "-----------------------------------------------------",
    "Checking for required module(s):"
)

$loggingInfo | ForEach-Object {
    Write-Output $_ | Out-File -FilePath "$LogPath$Logname" -Append
}

# Start script
# ... Connect to Graph

$appId = '<Id>' # Replace with your Id
$tenantId = '<TenantId>' # Replace with your TenantId
$secret = "<Secret>" # Replace with your Sercret

Connect-ToGraph -Tenant $tenantId -AppId $appId -AppSecret $secret

# Variables
$hostname = $env:computername 
$battery = Get-WmiObject Win32_Battery
$deviceId = Get-MgDevice -filter "DisplayName eq '$hostname'" | Select-Object -ExpandProperty Id
$user = Whoami /upn
$build = Test-Path 'HKLM:\Software\Microsoft\VERXMG'
$winVer = Get-WmiObject -Class Win32_OperatingSystem -Property Version
$userID = Get-MGUser -UserId $User | Select-Object -ExpandProperty Id
$upn = Get-MGUser -UserId $User | Select-Object -ExpandProperty UserPrincipalName
$title = Get-MGUser -UserId $UserID | Select-Object -ExpandProperty JobTitle
$location = Get-MGUser -UserId $UserID -Property onPremisesExtensionAttributes | Select-Object -ExpandProperty onPremisesExtensionAttributes | Select-Object -ExpandProperty ExtensionAttribute4
$department = Get-MGUser -UserId $UserID -Property onPremisesExtensionAttributes | Select-Object -ExpandProperty onPremisesExtensionAttributes | Select-Object -ExpandProperty ExtensionAttribute5
$business = Get-MGUser -UserId $UserID -Property onPremisesExtensionAttributes | Select-Object -ExpandProperty onPremisesExtensionAttributes | Select-Object -ExpandProperty ExtensionAttribute6


# Device Attritubutes
# (Chasis type, uBild method detection, and OS version) 

# ... (Chasis)
if ($battery -eq $null) {
    Write-Host 'Device type updated' -ForegroundColor Green
    Write-Output 'Device type updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute1 -Value Desktop
} else {
    Write-Host 'Device type updated' -ForegroundColor Green
    Write-Output 'Device type updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute1 -Value Laptop
}
# ... (Build method)
if ($build -eq $false) {
    Write-Host 'Build method updated' -ForegroundColor Green
    Write-Output 'Build method updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute2 -Value Autopilot
} elseif ($build -eq $true) {
    Write-Host 'Build method updated' -ForegroundColor Green
    Write-Output 'Build method updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute2 -Value OSD
}
# ... (Current OS Version)
if ($winVer -ne $null) {
    Write-Host 'Current OS updated' -ForegroundColor Green
    Write-Output 'Current OS updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute3 -Value $winVer.Version
} else {
    Write-Host 'Current OS unknown - WMI query failed' -ForegroundColor Red
    Write-Output 'Failed: Current OS unknown - WMI query failed' | Out-File -FilePath "$LogPath$Logname" -Append
    Update-Property -Attribute extensionAttribute3 -Value Unknown
}


# User Attributes
# (UPN, Position/Title, Usage Location, )

# ... UPN
if ($UserID -ne $null) {
    Write-Host 'UPN updated' -ForegroundColor Green
    Write-Output 'UPN updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute4 -Value $UPN
# ... Title
    Write-Host 'Title updated' -ForegroundColor Green
    Write-Output 'Title updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute5 -Value $title
# ... Location
    Write-Host 'Location updated' -ForegroundColor Green
    Write-Output 'Location updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute6 -Value $location
# ... Department
    Write-Host 'Department updated' -ForegroundColor Green
    Write-Output 'Department updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute7 -Value $department
# ... Business
    Write-Host 'Business updated' -ForegroundColor Green
    Write-Output 'Business updated successfully - ' | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
    Update-Property -Attribute extensionAttribute8 -Value $business


} else {
    $errorMsgs = @(
        'UPN not updated - UserID not found',
        'Title not updated - UserID not found',
        'Location not updated - UserID not found',
        'Department not updated - UserID not found',
        'Business not updated - UserID not found'
    )

    foreach ($errorMsg in $errorMsgs) {
        Write-Host $errorMsg -ForegroundColor Red
        Write-Output "Failed: $errorMsg - " | Out-File -FilePath "$LogPath$Logname" -Append -NoNewline
        $attributeName = "extensionAttribute" + ($errorMsgs.IndexOf($errorMsg) + 4)
        Update-Property -Attribute $attributeName -Value "UserID not found"
    }
}
