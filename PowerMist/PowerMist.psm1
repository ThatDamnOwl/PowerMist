## Constants
#ToDo Change all hashtables to lookups from API for more flexibility
# Mist API Endpoint
#Forcing TLS1.2 otherwise requests on certain machines will fail
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Import-module CommonFunctions -force
## Variables + getters and setters

$MistAPIURI = "https://api.mist.com/api/v1"
$MistSession = $null
$MistAPIKey = $null
$MistOrgID = $null
$MistUserCreds = $null
$MistVariablesSave = $false
$MistVariablesToSave = @("MistAPIKey","MistAPIURI","MistOrgID","MistVariablesSave","MistVariablesToSave")
$ModuleFolder = $MyInvocation.MyCommand.Path -replace "PowerMist\.psm1"

$MistCountries = @{
    "default"="GB"
}

$MistTimeZones = @{
    "default"="Etc/GMT"
}



Function Get-MistAPIURI
{
<#
.SYNOPSIS
Gets the current used APIUri for the mist module
.DESCRIPTION
Outputs the module variable that stores the URI used for API Calls to Mist
#>

    $MistAPIURI
}

Function Get-MistSession
{
<#
.SYNOPSIS
Gets the current used WebSession for the mist module
.DESCRIPTION
Outputs the module variable that stores the WebSession used for API Calls to Mist
#>   
    $MistSession
}

Function Get-MistAPIKey
{
<#
.SYNOPSIS
Gets the current used APIKey for the mist module
.DESCRIPTION
Outputs the module variable that stores the APIKey used for API Calls to Mist
#>   
    $MistAPIKey
}

Function Get-MistOrgID
{
<#
.SYNOPSIS
Gets the current used orgid for the mist module
.DESCRIPTION
Outputs the module variable that stores the currently selected orgid used for organisation specific api calls
#>   
    $MistOrgID
}

Function Get-MistUserCreds
{
<#
.SYNOPSIS
Gets the current used credentials for the mist module
.DESCRIPTION
Outputs the module variable that stores the credentials used for API Calls to Mist
#>   
    $MistUserCreds
}

Function Get-MistVariableSaveStatus
{
<#
.SYNOPSIS
Gets the current status of the variable save functions for the mist module
.DESCRIPTION
Outputs module variable save system status
#>
    $MistVariablesSave
}

Function Get-MistVariableSaveList
{
<#
.SYNOPSIS
Gets the current list of variables to save from the mist module
.DESCRIPTION
Outputs the list of module variable that will be saved
#>
    $MistVariablesToSave
}

Function Set-MistAPIURI
{
<#
.SYNOPSIS
Sets the APIURI to use for API Calls to Mist
.DESCRIPTION
Sets the APIURI to use for API Calls to Mist

The APIURI has to follow the following format:
(protocol)://(fqdn)/(apiroot)

by default it is 

https://api.mist.com/api/v1

This variable should never change.
.EXAMPLE
Set-MistAPIURI -NewMistAPIURI https://api.mist.com/api/v1
#>
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $NewMistAPIURI
    )
    set-variable -scope Global -name MistAPIURI -value $NewMistAPIURI
}

Function Refresh-MistSession
{
<#
.SYNOPSIS
Refreshes the Web session to use for API Calls to Mist
.DESCRIPTION
Refreshes or creates a new API Session
.EXAMPLE
Refresh-MistSession -token
#>
    param
    (
        [switch]
        $token,
        [switch]
        $credentials
    )

    if (($token) -or ($MistAPIKey -ne $null))
    {
        Invoke-MistTokenBasedLogin
    }
    elseif ($credentials -or ($MistUserCreds -ne $null))
    {
        Invoke-MistCredentialBasedLogin
    }
    else
    {
        throw "No possible authentication process designated, please check your credentials and try again"
    }
}

Function Set-MistAPIKey
{
    param
    (
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]
        $NewMistAPIKey
    )
    set-variable -scope Global -name MistAPIKey -value $NewMistAPIKey
}

Function Set-MistAPIKeyFromPath
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]
        $NewMistAPIKeyPath
    )

    $NewMistAPIKey = Import-MistAPIKey $NewMistAPIKeyPath

    set-variable -scope Global -name MistAPIKey -value $NewMistAPIKey
}

Function Set-MistOrgID
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $NewMistOrgID
    )
    set-variable -scope Global -name MistOrgID -value $NewMistOrgID
}

Function Set-MistUserCreds
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PsCredential]
        $NewMistUserCreds
    )
    set-variable -scope Global -name MistUserCreds -value $NewMistUserCreds
}

Function Set-MistVariablesSave
{
    param
    (
        [switch]
        $enable,
        [switch]
        $disable
    )

    if ($enable)
    {
        set-variable -scope Global -name MistVariablesSave -value $true
    }
    elseif ($disable)
    {
        set-variable -scope Global -name MistVariablesSave -value $false
    }
    else
    {
        throw "No flag set, please call this function with either -enable or -disable"
    }
}

Function Set-MistVariablesToSave
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Object[]]
        $NewVariablesToSave
    )
    set-variable -scope Global -name MistVariablesToSave -value $NewVariablesToSave
}

Function Add-MistVariablesToSave
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Object[]]
        $NewVariablesToSave
    )
    $TempVars = (($MistVariablesToSave + $NewVariablesToSave) | select -unique)


    set-variable -scope Global -name MistVariablesToSave -value $TempVars
}

Function Invoke-MistVariableSave
{
    $AllVariables = Get-Variable -scope Global | where {$_.name -match "Mist"} | where {$_.name -in $MistVariablesToSave}
    $SavePath = "$ModuleFolder\$($ENV:Username)-Variables.json"

    Write-Debug "Starting save job to $SavePath"

    Invoke-VariableJSONSave -ModuleName "PowerMist" -SavePath $SavePath -Variables $AllVariables -verbosepreference:$VerbosePreference
}

Function Invoke-MistVariableLoad
{
    $SavePath = "$ModuleFolder\$($ENV:Username)-Variables.json"

    if (test-path $SavePath)
    {
        Write-Debug "Starting load job from $SavePath"

        $Variables = Invoke-VariableJSONLoad -LoadPath $SavePath -Verbosepreference:$VerbosePreference

        foreach ($Variable in $Variables)
        {
            Write-Debug "Importing variable $($Variable.name)"
            set-variable -name $Variable.name -Value $Variable.Value -scope Global
        } 
    }
}

## Import Common Functions (if they exist)
$CommonFunctions = "$(Split-Path -parent $MyInvocation.MyCommand.Path)\CommonFunctions.psm1"

if (test-path $CommonFunctions)
{
   Import-Module $CommonFunctions
}
else {
    $CommonFunctions = Get-Module CommonFunctions -listavailable
    if ($CommonFunctions)
    {
        Import-Module CommonFunctions
    }
    else {
        Throw "CommonFunctions not found, please install the module"
    }
}



## Functions

### Formatting/Data manipulation functions

Import-module "$ModuleFolder\PowerMist_Auth.psm1" -force

### Site Manipulation functions

Import-module "$ModuleFolder\PowerMist_Sites.psm1"

### Org Manipulation functions

Import-module "$ModuleFolder\PowerMist_Orgs.psm1"

Function Get-MistSiteClients
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Get-PageinatedList $MistSession "$MistAPIURI/sites/$SiteID/stats/clients"
}

Function Get-MistSiteMap
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $MapID
    )
    #"$MistAPIURI/api/v1/sites/$SiteID/maps" 
    return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/maps/$MapID" -WebSession $MistSession
}

Function Get-MistSiteMaps
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    #"$MistAPIURI/api/v1/sites/$SiteID/maps" 
    return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/maps" -WebSession $MistSession
}

Function Get-MistSiteDevice
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $DeviceID
    )
    #"$MistAPIURI/api/v1/sites/$SiteID/maps" 
    return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/devices/$DeviceID" -WebSession $MistSession
}

Function Disconnect-MistWAPfromEdge 
{
    param
    (
  
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $MEID, 
        [Parameter(Mandatory=$true)]
        [string[]]
        $DisconnectWAPs
    )
    
    Write-Host $DisconnectWAPs

    $Hyphenated = @()

    if ($DisconnectWAPs -notmatch "-")
    {
        foreach ($DisconnectWAP in $DisconnectWAPs)
        {
            $Hyphenated += Get-MistHyphenMAC $DisconnectWAP
        }
    }

    #Write-Host $Hyphenated
    
    $WAPArr = "{
    ""macs"": $(if ($DisconnectWAPs -ne $null) {Get-JSONArray $Hyphenated} else {"[ ]"})
    }"

    Write-Host "$MistAPIURI/orgs/$MistOrgID/mxedges/$MEID/services/tunterm/disconnect_aps"

    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/mxedges/$MEID/services/tunterm/disconnect_aps" -WebSession $MistSession -Method Post -Body $WAPArr -ContentType "application/json"
}

Function Disconnect-MistWAPsfromEdgeAtRandom
{
    param
    (
  
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $MEID, 
        [Parameter(Mandatory=$true)]
        [int]
        $percentage
    )

    #Write-Host $Hyphenated
    
    $WAPArr = "{
    ""percentage"": $percentage
    }"

    Write-Host "$MistAPIURI/orgs/$MistOrgID/mxedges/$MEID/services/tunterm/disconnect_aps"

    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/mxedges/$MEID/services/tunterm/disconnect_aps" -WebSession $MistSession -Method Post -Body $WAPArr -ContentType "application/json"
}

Function Import-MistSites
{
    param
    (

    )
    $Sites = import-csv -LiteralPath $CSV
    $ExistingSites = Get-AllSites $MistSession
    foreach ($Site in $Sites)
    {
        $SiteName = "$($Site.'Site Code') - $($Site.'Branch Name')"

        if (($ExistingSites | where {$_.name -match $Site.'Site Code'}) -eq $null)
        {
            Write-Host "$SiteName Doesn't exist"
            New-Site $MistSession $SiteName 
        }
        else
        {
            Write-Host "$SiteName Exists"
        }
    }
}

## This is a bad way of storing the key, I will be replacing this

Function Import-MistAPIKey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $APIKeyPath
    )
    $SplitPath = $APIKeyPath -split "\\"
    $APIID = $SplitPath[$SplitPath.length - 1] -replace "\.txt",""
    $EncString = Get-Content $APIKeyPath | ConvertTo-SecureString
    $APIKeyEnc = New-Object System.Management.Automation.PsCredential($APIID, $EncString)
    $APIKey = @{"ID"=$APIID;"Key"=$APIKeyEnc.GetNetworkCredential().Password.ToString()}
    $APIKey
}

Function Get-JSONArray
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [object[]]
        $InputArray
    )

    $JSONArray = "["

    foreach ($Input in $InputArray)
    {
        $JSONArray += """$Input"", "
    }

    $JSONArray = $JSONArray.Substring(0,$JSONArray.Length - 2)

    $JSONArray += "]"

    return $JSONArray
}

Function Export-MistAPIKey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $StoragePath,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $APIKey
    )
    $Creds = New-Object System.Management.Automation.PsCredential($APIKey["ID"], (ConvertTo-SecureString -asplaintext $APIKey["Key"] -Force))
    $Creds.Password | ConvertFrom-SecureString | Set-Content $StoragePath
}

Function Get-MistHyphenMAC
{
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [String[]]
        $MACString
    )
    $ReturnMacs = @()
    foreach ($mac in $MACString)
    {
        #write-host $mac
        if ($mac -match ":")
        {
            $mac = $mac -replace ":"
        }

        for ($x = 10; $x -gt 0; $x = $x - 2)
        {
            $mac = $mac.Insert($x,"-")
        }

        $ReturnMacs += $mac
    }
    return $ReturnMacs
}

Function Get-MistDeviceManagementURI
{
    param 
    (
        $MistDevice
    )
    return "https://manage.mist.com/admin/?org_id=$($MistDevice.org_id)#!$($MistDevice.type)/detail/$($MistDevice.id)/$($MistDevice.site_id)"
}


## Load any saved variables

Invoke-MistVariableLoad

if ($MistAPIKey -ne $null)
{
    Invoke-MistTokenBasedLogin
}
elseif ($MistUserCreds -ne $null)
{
    Invoke-MistCredentialBasedLogin
}
else
{
    Write-Debug "No credentials stored"
}