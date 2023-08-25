#Requires -Version 5.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Script will add user to local admin account base on AAD membership
   
.DESCRIPTION
    
.NOTES
    Filename: Provision-UserRights.ps1
    Version: 1.3
    Author: Kevin Odom
    Created:     8/4/2023
    Updated:     X

    Version history
    1.1 - (2022-01-24) Updated script to pull UPN instead of EID
     
#> 
Clear-Host
Start-Transcript -Path c:\ProgramData\Admin_Rights.log -Append -Force

####################################################
#
# CONFIG
#
####################################################

    #Required credentials - Get the client_id and client_secret from the app when creating it in Azure AD
    #$client_id = "" #App ID - Powershell API Access
    #$client_secret = "" #API Access Key Password

    $client_id = "appid"
    $client_secret = "secret"

    #tenant_id can be read from the azure portal of your tenant (check the properties blade on your azure active directory)
    $tenant_id = "tenantid" #Directory ID

    #Object ID of the group that holds users, whom need to be local admin on AAD joined Intune Devices
    $localAdminGroupID = "7049b44e-551a-4665-b41c-d8ff64a4163a"
    #$objectID = "7049b44e-551a-4665-b41c-d8ff64a4163a"

    #Special params for some advanced modification
    $global:graphApiVersion = "v1.0" #should be "v1.0"
    

####################################################
#
# FUNCTIONS
#
####################################################

Function Get-AuthToken {
    
    <#
    .SYNOPSIS
    This function is used to get an auth_token for the Microsoft Graph API
    .DESCRIPTION
    The function authenticates with the Graph API Interface with client credentials to get an access_token for working with the REST API
    .EXAMPLE
    Get-AuthToken -TenantID "0000-0000-0000" -ClientID "0000-0000-0000" -ClientSecret "sw4t3ajHTwaregfasdgAWREGawrgfasdgAWREGw4t24r"
    Authenticates you with the Graph API interface and creates the AuthHeader to use when invoking REST Requests
    .NOTES
    NAME: Get-AuthToken
    #>

    param
    (
        [Parameter(Mandatory=$true)]
        $TenantID,
        [Parameter(Mandatory=$true)]
        $ClientID,
        [Parameter(Mandatory=$true)]
        $ClientSecret
    )
    
    try{
        # Define parameters for Microsoft Graph access token retrieval
        $resource = "https://graph.microsoft.com"
        $authority = "https://login.microsoftonline.com/$TenantID"
        $tokenEndpointUri = "$authority/oauth2/token"
  
        # Get the access token using grant type client_credentials for Application Permissions
        $content = "grant_type=client_credentials&client_id=$ClientID&client_secret=$ClientSecret&resource=$resource"

        $response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing

        Write-Host "Got new Access Token!" -ForegroundColor Green
        Write-Host

        # If the accesstoken is valid then create the authentication header
        if($response.access_token){
    
        # Creating header for Authorization token
    
        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $response.access_token
            'ExpiresOn'=$response.expires_on
            }
    
        return $authHeader
    
        }
    
        else{
    
        Write-Error "Authorization Access Token is null, check that the client_id and client_secret is correct..."
        break
    
        }

    }
    catch{
    
        FatalWebError -Exeption $_.Exception -Function "Get-AuthToken"
   
    }

}

####################################################

Function Get-ValidToken {

    <#
    .SYNOPSIS
    This function is used to identify a possible existing Auth Token, and renew it using Get-AuthToken, if it's expired
    .DESCRIPTION
    Retreives any existing Auth Token in the session, and checks for expiration. If Expired, it will run the Get-AuthToken Fucntion to retreive a new valid Auth Token.
    .EXAMPLE
    Get-ValidToken
    Authenticates you with the Graph API interface by reusing a valid token if available - else a new one is requested using Get-AuthToken
    .NOTES
    NAME: Get-ValidToken
    #>

    #Fixing client_secret illegal char (+), which do't go well with web requests
    $client_secret = $($client_secret).Replace("+","%2B")
    
    # Checking if authToken exists before running authentication
    if($global:authToken){
    
        # Get current time in (UTC) UNIX format (and ditch the milliseconds)
        $CurrentTimeUnix = $((get-date ([DateTime]::UtcNow) -UFormat +%s)).split((Get-Culture).NumberFormat.NumberDecimalSeparator)[0]
                
        # If the authToken exists checking when it expires (converted to minutes for readability in output)
        $TokenExpires = [MATH]::floor(([int]$authToken.ExpiresOn - [int]$CurrentTimeUnix) / 60)
    
            if($TokenExpires -le 0){
    
                Write-Host "Authentication Token expired" $TokenExpires "minutes ago! - Requesting new one..." -ForegroundColor Green
                $global:authToken = Get-AuthToken -TenantID $tenant_id -ClientID $client_id -ClientSecret $client_secret
    
            }
            else{

                Write-Host "Using valid Authentication Token that expires in" $TokenExpires "minutes..." -ForegroundColor Green
                Write-Host

            }

    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
       
        # Getting the authorization token
        $global:authToken = Get-AuthToken -TenantID $tenant_id -ClientID $client_id -ClientSecret $client_secret
    
    }
    
}
    
####################################################

Function FatalWebError {

    <#
    .SYNOPSIS
    This function will output mostly readable error information for web request related errors.
    .DESCRIPTION
    Unwraps most of the exeptions details and gets the response codes from the web request, afterwards it stops script execution.
    .EXAMPLE
    FatalWebError -Exception $_.Exception -Function "myFunctionName"
    Shows the error message and the name of the function calling it.
    .NOTES
    NAME: FatalWebError
    #>

    param
    (
        [Parameter(Mandatory=$true)]
        $Exeption, # Should be the execption trace, you might try $_.Exception
        [Parameter(Mandatory=$true)]
        $Function # Name of the function that calls this function (for readability)
    )

#Handles errors for all my Try/Catch'es

        $errorResponse = $Exeption.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Failed to execute Function : $Function" -f Red
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Host "Request to $Uri failed with HTTP Status $($Exeption.Response.StatusCode) $($Exeption.Response.StatusDescription)" -f Red
        write-host
        break

}

####################################################

Function Get-AADGroupMembers(){
   
   #####
       
    param
    (
        [Parameter(Mandatory=$true)]
        $objectID
    )

    #$Resource = "myorganization/groups"
    $Resource = "/groups/$objectID/members?`$top=999"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    try {

        Return (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }
    
    catch {
    
        FatalWebError -Exeption $_.Exception -Function "Get-AADGroupMembers"
    
    }

    
}

####################################################

Function Get-LocalAdmins {

Invoke-Command -ScriptBlock{
   $admembers = Invoke-Expression -command "Net Localgroup Administrators"
   $admembers[6..($admembers.Length-3)]
}
}

####################################################

Function Get-AADUserDevices(){
   
   #####GET https://graph.microsoft.com/v1.0/users/{usersId}/managedDevices/{managedDeviceId}
       
    param
    (
        [Parameter(Mandatory=$true)]
        $user
    )

    #$Resource = "myorganization/groups"
    $Resource = "/users/$user/managedDevices"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    try {

        Return (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }
    
    catch {
    
        FatalWebError -Exeption $_.Exception -Function "Get-AADUserDevices"
    
    }

    
}

####################################################
#
# EXECUTION
#
####################################################

#Wait For Connection. 

do { 
    Write-Host "Waiting for connection" 
    Start-Sleep -Seconds 5 
} until (Test-Connection 'www.google.com' -Quiet -Count 1) 

Write-Host "CONNECTION SUCCEEDED" -ForegroundColor Green

Write-Host "Adding required members to the built-in Administrators group." -ForegroundColor Magenta
Write-Host

#Calling Microsoft to see if they will give us access with the parameters defined in the config section of this script.
Get-ValidToken

#Getting the members of the predefined groups (see config section)
$localAdmins = Get-AADGroupMembers -objectID $localAdminGroupID


##############

#$cu = Get-Itemproperty "Registry::\HKEY_USERS\*\Volatile Environment" | Select-Object USERNAME -ExpandProperty USERNAME
#$user = $cu + '@Honeywell.com'
#$user = whoami /upn
$user = [string]$($1='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\';if(Test-Path -Path $1){(Get-ItemProperty -Path ('{0}\{1}' -f ($1,(Get-ChildItem -Path $1).Name.Split('\')[-1])) -Name 'UserEmail' | Select-Object -ExpandProperty 'UserEmail')}else{''})
$members = Get-AADGroupMembers -objectID $localAdminGroupID
$id = Get-WmiObject -Class Win32_ComputerSystem | Select UserName -ExpandProperty Username
$gid = Get-LocalAdmins
$devices = Get-AADUserDevices -user $user | Where-Object {$_.deviceEnrollmentType -eq "windowsAzureADJoin"} | Select-Object -ExpandProperty deviceName
$hostname = $env:COMPUTERNAME
#$hostname = "test"


Write-Host Current logged in user: $user -ForegroundColor Yellow
Write-Host Devices registered to $user -ForegroundColor Yellow
Write-Host $devices -ForegroundColor Yellow 

###

If (($members.userPrincipalName -contains $user) -and ($gid -notcontains $id) -and ($devices -contains $hostname) -and ($id -notlike "$localadmin")) 

{
      Write-Host $user exists in the AzureAD group -ForegroundColor Green
      Write-Host $hostname is a Registered Device for $user -Foreground Green
      Write-Host Adding $user to the Local Administrators group -ForegroundColor Green 
      Add-LocalGroupMember -Group "Administrators" -Member "AzureAD\$user"
      Write-Host Current users in the local admin group: 
      Get-LocalAdmins
      }
       
Elseif (($members.userPrincipalName -notcontains $user) -and ($id -notlike "$localadmin"))

{
      Write-Host $user does not exist in the AzureAD group -ForegroundColor Green 
      Write-Host Removing $id from local admin group -ForegroundColor Green 
      Remove-LocalGroupMember -Group "Administrators" -Member "AzureAD\$user" -ErrorAction SilentlyContinue
      Write-Host Current users in the local admin group: 
      Get-LocalAdmins
}

Elseif (($devices -notcontains $hostname) -and ($id -notlike "$localadmin"))

{
      Write-Host $hostname is not a registered device for $user -ForegroundColor Red
      Write-Host Removing $id from local admin group -ForegroundColor Green 
      Remove-LocalGroupMember -Group "Administrators" -Member "AzureAD\$user" -ErrorAction SilentlyContinue
      Write-Host Current users in the local admin group:
      Get-LocalAdmins
}

Else

 {

      Write-Host $user does not exist in the AzureAD group is already part of the local admin group or $hostname is not a Device registered to $user -ForegroundColor Green
      Write-Host Current users in the local admin group: 
      Get-LocalAdmins
}

Stop-Transcript


