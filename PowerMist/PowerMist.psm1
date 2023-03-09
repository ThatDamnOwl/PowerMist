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
$ModuleFolder = (Get-Module PowerMist -ListAvailable).path -replace "PowerMist\.psm1"

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
    set-variable -scope 1 -name MistAPIURI -value $NewMistAPIURI
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
    set-variable -scope 1 -name MistAPIKey -value $NewMistAPIKey
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

    set-variable -scope 1 -name MistAPIKey -value $NewMistAPIKey
}

Function Set-MistOrgID
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $NewMistOrgID
    )
    set-variable -scope 1 -name MistOrgID -value $NewMistOrgID
}

Function Set-MistUserCreds
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PsCredential]
        $NewMistUserCreds
    )
    set-variable -scope 1 -name MistUserCreds -value $NewMistUserCreds
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
        set-variable -scope 1 -name MistVariablesSave -value $true
    }
    elseif ($disable)
    {
        set-variable -scope 1 -name MistVariablesSave -value $false
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
    set-variable -scope 1 -name MistVariablesToSave -value $NewVariablesToSave
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


    set-variable -scope 1 -name MistVariablesToSave -value $TempVars
}

Function Invoke-MistVariableSave
{
    $AllVariables = Get-Variable -scope 1 | where {$_.name -match "Mist"} | where {$_.name -in $MistVariablesToSave}
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
            set-variable -name $Variable.name -Value $Variable.Value -scope 1
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

Function Get-PageinatedList
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $ListURI, 
        [Parameter(Mandatory=$false)]
        [ValidateRange(10,100)]
        [int]
        $PageSize = 100,
        [Parameter(Mandatory=$false)]
        [ValidateRange(1,100)]
        [int]
        $StartPage = 1
    )


    $Results = @()
    $Page = $StartPage

    $Operator = "?"

    if ($ListURI -match "\?")
    {
        $Operator = "&"
    }

    Do 
    {

        $WebRequest = Invoke-WebRequest -uri "$($ListURI)$($Operator)limit=$PageSize&page=$Page" -WebSession $MistSession -ContentType "application\json"
        
        $Results += ConvertFrom-Json $WebRequest.content
        
        $Page++
        $PageLimit = $WebRequest.Headers.'X-Page-Limit'
        $PagePage = $WebRequest.Headers.'X-Page-Page'
        $PageTotal = $WebRequest.Headers.'X-Page-Total'
        if ($PageLimit -gt 0)
        {
            $GettingPages = ($Page -le [math]::Ceiling($PageTotal/$PageLimit))        
            Write-Log "Retrieved $PagePage of $([math]::Ceiling($PageTotal/$PageLimit)), there is $PageTotal entries, the pages are $PageLimit Items Long" 
        } 
        else 
        {
            $GettingPages = $false
            Write-Log "Returned no clients"
        } 
    }
    while ($GettingPages)

    return $Results
}

Function Invoke-MistCredentialBasedLogin
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PsCredential]
        $Creds
    )
    if ($Creds -eq $null)
    {
        $Creds = Get-Credential
    }

    $LoginJson = "{""email"": ""$($Creds.UserName)"", ""password"": ""$($Creds.GetNetworkCredential().Password)""}"

    $LoginDeets = Invoke-WebRequest -uri "$MistAPIURI/login" -Method POST -Body $LoginJson -ContentType application/json -SessionVariable 'Session'
    
    $Session.Headers.add("X-CSRFTOKEN", ((($MistSession.Cookies.GetCookieHeader("$MistAPIURI") -split ";")[0] -split "=")[1]))

    $UserInfo = Get-MistUserInfo $MistSession

    if ($UserInfo.two_factor_required)
    {
        Write-Host "2FA is enabled for this account, please enter your 2FA key"
        $2FA = read-host

        $2FAJson = "{""two_factor"": ""$2FA""}"

        $LoginDeets = Invoke-WebRequest -uri "$MistAPIURI/login/two_factor" -Method POST -Body $2FAJson -ContentType application/json -WebSession $MistSession
        $Session.headers.'X-CSRFTOKEN' = ((($MistSession.Cookies.GetCookieHeader("$MistAPIURI") -split ";")[0] -split "=")[1])
    }
    else {
        
    }
    set-variable -Scope 1 -Name MistSession -Value $Session
}

Function Invoke-MistTokenBasedLogin
{
    param
    (
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]
        $APIKey
    )

    if ((-not $APIKey) -and ($MistAPIKey))
    {
        $APIKey = $MistAPIKey
    }
    else
    {
        throw "No API Key provided and no API Key stored, please provide an API Key"
    }

    if (-not $MistAPIKey)
    {
        set-variable -scope 1 -name MistAPIKey -Value $APIKey
    }

    $LoginDeets = Invoke-RestMethod -uri "$MistAPIURI/self" -Headers @{"Authorization"="Token $($APIKey["Key"])"} -SessionVariable Session -Method get
    set-variable -Scope 1 -Name MistSession -Value $Session
}

Function Get-MistUserInfo
{
    param
    (

    )
    return Invoke-RestMethod -uri "$MistAPIURI/self"  -WebSession $MistSession -Method get
}

Function Get-MistSite
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID"  -WebSession $MistSession -Method get
}

Function Get-MistSiteSettings
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/setting"  -WebSession $MistSession -Method get
}

Function Set-MistSiteWlan
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $WLANID,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]
        $WLANSettings
    )
    return Invoke-WebRequest -uri "$MistAPIURI/sites/$SiteID/wlans/$WLANID" -WebSession $MistSession -Method Put -Body ($WLANSettings | convertto-json) -ContentType "application/json"
}

Function Set-MistSiteSettings
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]
        $SiteSettings
    )
    $AllowedFields = @(
        "rtsa",
        "wifi",
        "persist_config_on_device",
        "device_updown_threshold",
        "radio_config",
        "enable_channel_144",
        "mesh",
        "rogue",
        "led",
        "vars",
        "auto_upgrade",
        "status_portal",
        "remote_syslog",
        "engagement",
        "analytic",
        "flags",
        "ble_config",
        "wids",
        "proxy",
        "ssh_keys",
        "mxtunnel"
    )
    foreach ($Property in $SiteSettings.PSObject.Properties)
    {
        if ($AllowedFields -notcontains $Property.name)
        {
            Write-Warning "$($Property.name) is not an allowed field, removing from the settings"
            $SiteSettings.PSObject.Properties.remove($Property.name)
        }
    }
    #$SiteSettings
    return Invoke-WebRequest -uri "$MistAPIURI/sites/$SiteID/setting" -WebSession $MistSession -Method Put -Body ($SiteSettings | convertto-json) -ContentType "application/json"
}

Function Get-MistSiteWlans
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$false)]
        [switch]
        $Resolve
    )
    return Get-PageinatedList -ListURI "$MistAPIURI/sites/$SiteID/wlans/derived?resolve=$Resolve"
}

Function Get-MistSiteGroups
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/wlans"  -WebSession $MistSession -Method get
}

Function Get-MistSitePSK
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$false)]
        [String]
        $Name
    )
    if ($Name -ne $null)
    {
        return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/psks?name=$Name" 
    }
    else
    {
        return Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/psks" 
    }
}

Function Add-MistSitePSK
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]
        $PSKSettings
    )
    Invoke-WebRequest -uri "$MistAPIURI/sites/$SiteID/psks" -WebSession $MistSession -Method Post -Body ($PSKSettings | convertto-json) -ContentType "application/json"
}

Function Set-MistSitePSK
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]
        $PSKSettings
    )
    return Invoke-WebRequest -uri "$MistAPIURI/sites/$SiteID/wlans/$WLANID" -WebSession $MistSession -Method Put -Body ($PSKSettings | convertto-json) -ContentType "application/json"
}

Function Initialize-MistSitePSKSettings
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $name,
        [Parameter(Mandatory=$true)]
        [string]
        $passphrase,
        [Parameter(Mandatory=$true)]
        [string]
        $ssid,
        [Parameter(Mandatory=$false)]
        [string]
        $usage = "multi",
        [Parameter(Mandatory=$false)]
        [string]
        $role,
        [Parameter(Mandatory=$false)]
        [int]
        $vlanId,
        [Parameter(Mandatory=$false)]
        [string]
        $mac,
        [Parameter(Mandatory=$false)]
        [int]
        $expireTime = $null,
        [Parameter(Mandatory=$false)]
        [string]
        $notes,
        [Parameter(Mandatory=$false)]
        [boolean]
        $notifyExpiry,
        [Parameter(Mandatory=$false)]
        [int]
        $expiryNotificationTime,
        [Parameter(Mandatory=$false)]
        [boolean]
        $notifyOnCreateOrEdit,
        [Parameter(Mandatory=$false)]
        [string]
        $email
    )

    $BaseObject = [pscustomobject]@{
        "name" = $Name
        "passphrase" = $Passphrase
        "ssid" = $SSID
        "expire_time" = $ExpireTime
        "role" = $role
    }

    if ($ExpireTime -eq 0)
    {
        $BaseObject | add-member -name expire_time -Value $null -MemberType NoteProperty -force
    }

    if ($mac -eq "")
    {
        $BaseObject | add-member -name "-mac" -Value $true -MemberType NoteProperty -force
    }

    ## This feels dodgy but works
    $ExtraVars = Get-Variable -scope 0 | where {($_.name -notin @("name","passphrase","ssid","expireTime","BaseObject","true","false","role")) -and `
                                                ($_.value -ne $null) -and `
                                                ($_.name -cmatch "^[a-z]{1}")}

    foreach ($ExtraVar in $ExtraVars)
    {
        if (($ExtraVar.value -ne $null) -and ($ExtraVar.value -ne 0) -and ($ExtraVar.value -ne ""))
        {
            $Name = ($ExtraVar.name -creplace "([A-Z]{1}[a-z]*)",'_$1').tolower()
            $BaseObject | add-member -name $Name -Value $ExtraVar.value -MemberType NoteProperty -force
        }
    }

    return $BaseObject
}

Function Get-MistOrganizations
{
    param
    (

    )
    return (Get-MistUserInfo $MistSession).privileges | where {$_.Scope -eq "org"}
}

Function Get-MistSiteAlarms
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )

    Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/alarms/search"
}

Function Get-MistOrgWlans
{
    param
    (

    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/wlans" -WebSession $MistSession
}

Function Get-MistOrgTemplate
{
        param
    (

        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $TemplateID
    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/templates/$TemplateID" -WebSession $MistSession
}

Function Get-MistOrgWlan
{
    param
    (

        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgWlanID
    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/wlans/$OrgWlanID" -WebSession $MistSession
}

Function Get-MistOrgTemplates
{
    param
    (

    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/templates" -WebSession $MistSession
}

Function Get-MistOrgGroup
{
    param
    (

        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $GroupID
    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/sitegroups/$GroupID" -WebSession $MistSession
}

Function Get-MistRFTemplates
{
    param
    (

    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/rftemplates" -WebSession $MistSession
}

Function Get-MistOrgPsks
{
    param
    (

    )

    Get-PageinatedList -ListUri "$MistAPIURI/orgs/$MistOrgID/psks" -PageSize 100
}

Function Get-MistGroupWlans
{
    param
    (

        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $GroupID
    )
    $Wlans = @() 
    $Templates = Get-MistOrgTemplates $MistSession $MistOrgID 
    $OrgWlans = Get-MistOrgWlans $MistSession $MistOrgID
    
    foreach ($Template in $Templates)
    {
        Write-verbose "Checking Template - $($Template.id)"
        if ($Template.applies.sitegroup_ids -contains $GroupID)
        {
            Write-verbose "Template - $($Template.id) is applied to the group"            
            foreach ($Wlan in $OrgWlans)
            {
                if ($Wlan.template_id -eq $Template.id)
                {
                    Write-verbose "WLAN - $($Wlan.id) is part of the template"
                    $Wlans += @($Wlan)             
                }
                else
                {
                    Write-verbose "WLAN - $($Wlan.id) is not part of the template"
                }
            }
        }
        else
        {
            Write-verbose "Template - $($Template.id) is not applied to the group"
        }
    }
    return $Wlans
}

Function Get-MistSites
{
    param
    (

    )
    Get-PageinatedList -ListURI "$MistAPIURI/orgs/$MistOrgID/sites" -PageSize 100
}

Function Get-MistSiteDeviceStats
{

    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$false)]
        [ValidatePattern("(ap|switch|all)")]
        [String]
        $DeviceType = "all",
        [Parameter(Mandatory=$false)]
        [ValidatePattern("(all|connected|disconnected)")]
        [String]
        $DeviceStatus = "all"
    )
    Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/stats/devices?type=$($DeviceType)&status=$($DeviceStatus)" -WebSession $MistSession
}

Function Get-MistSiteGroups
{
    param
    (

    )
    Invoke-RestMethod -uri "$MistAPIURI/orgs/$MistOrgID/sitegroups" -WebSession $MistSession
}

Function Get-MistInventory
{
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )

    if ($OrgID -eq $null)
    {
        $OrgID = $MistOrgID
    }

    Invoke-RestMethod -uri "$MistAPIURI/orgs/$OrgID/inventory" -WebSession $MistSession
}

Function Get-MistSiteInventory
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/devices" -WebSession $MistSession
}

Function Get-MistAPIKeys
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $APIKeyPath
    )
    Invoke-RestMethod -uri "$MistAPIURI/self/apitokens" -WebSession $MistSession
}

Function New-MistAPIKey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $APIKeyPath
    )
    $TempAPIKey = Invoke-WebRequest -uri "$MistAPIURI/self/apitokens" -WebSession $MistSession -Method Post -Body $null -ContentType "application/json"
    
    $APIKey = @{"ID" = ""; "Key" = ""}
    $ignore = ($TempAPIKey.Content -match """id"":""[^""]*""")
    $APIKey["ID"] = ($Matches[0] -split ":")[1] -replace """"
    $ignore = ($TempAPIKey.Content -match """key"":""[^""]*""")
    $APIKey["Key"] = ($Matches[0] -split ":")[1] -replace """"

    return $APIKey
}

Function New-MistOrgPSK
{
    param
    (
        $Name,
        $Passphrase,
        $SSID,
        $Usage = 0,
        $VLAN = ""
    )

    $PSKInfo = "
{
    ""name"": ""$Name"",
    ""ssid"": ""$SSID"",
    ""passphrase"": ""$Passphrase"",
    ""usage"": ""0"",
    ""vlan"": ""$VLAN""
}
"
    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/psks" -WebSession $MistSession -Method Post -Body $PSKInfo -ContentType "application/json"
}

Function Update-MistOrgPSK
{
    param
    (
        $PSKs
    )

    if ($PSKs.count -eq $Null)
    {
        $PSKs = @($PSKs)
    }

    $PSKJSON = convertto-json $PSKs

    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/psks" -Websession $MistSession -Method PUT -Body $PSKJSON -ContentType "application/json"
}

Function Get-MistOrgDeviceStats
{
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $DeviceID
    )

    $ListURI = "$MistAPIURI/orgs/$MistOrgID/stats/devices"

    $AllWaps = Get-PageinatedList -ListURI $ListURI -PageSize 100

    if ($DeviceID)
    {
        $AllWaps = $AllWaps | where {$_.id -eq $DeviceID}
    }

    return $AllWaps | where {$_.ip.Length -gt 0}
}

Function Get-MistOrgEdges
{
    param
    (

    )

    $ListURI = "$MistAPIURI/orgs/$MistOrgID/mxedges"

    $Edges = Get-PageinatedList -ListURI $ListURI -PageSize 100

    return $Edges
}

Function New-MistSite 
{
    param
    (

        [Parameter(Mandatory=$true)]
        [String]
        $SiteName,
        [Parameter(Mandatory=$false)]
        [String]
        $TimeZone = "Etc/GMT",
        [Parameter(Mandatory=$false)]
        [String]
        $Country = "GB",
        [Parameter(Mandatory=$false)]
        [String]
        $Address = "Greenwich, London SE10 8XJ, United Kingdom", 
        [Parameter(Mandatory=$false)]
        [Object[]]
        $SiteGroups
    )
    
    $SiteProperties = "{
    ""name"": ""$SiteName"",
    ""timezone"": ""$TimeZone"",
    ""country_code"": ""$Country"",
    ""secpolicy_id"": """",
    ""alarmtemplate_id"": """",
    ""sitegroup_ids"": $(if ($SiteGroups -ne $null) {Get-JSONArray $SiteGroups} else {"[ ]"}),
    ""address"": ""$Address""
}"
    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/sites" -WebSession $MistSession -Method Post -Body $SiteProperties -ContentType "application/json"
}

Function New-MistSiteGroup
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $Name           
    )

    $SiteGroupProperties = "{
    ""name"": ""$Name""
}"

    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/sitegroups" -WebSession $MistSession -Method Post -Body $SiteGroupProperties -ContentType "application/json" 
}

Function Reset-MistOrgEdgePorts 
{
    param
    (
  
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $MEID, 
        [Parameter(Mandatory=$true)]
        [Object[]]
        $BouncePorts
    )
    $Ports = "{
    ""ports"": $(if ($BouncePorts -ne $null) {Get-JSONArray $BouncePorts} else {"[ ]"})
    }"
    ## Write-Host "$MistAPIURI/orgs/$MistOrgID/mxedges/$MEID/services/tunterm/bounce_port"
    ## Write-Host "$BouncePorts"
    ## Write-Host $Ports
    Invoke-WebRequest -uri "$MistAPIURI/orgs/$MistOrgID/mxedges/$MEID/services/tunterm/bounce_port" -WebSession $MistSession -Method Post -Body $Ports -ContentType "application/json"
}

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