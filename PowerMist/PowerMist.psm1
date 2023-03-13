## Constants
#ToDo Change all hashtables to lookups from API for more flexibility
# Mist API Endpoint
#Forcing TLS1.2 otherwise requests on certain machines will fail
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Import-module CommonFunctions -force
## Variables + getters and setters

$MistAPIURI = "https://api.mist.com/api/v1"
$MistSession = $null
$MistAPIToken = $null
$MistOrgID = $null
$MistUserCreds = $null
$MistVariablesSave = $false
$MistVariablesToSave = @("MistAPIToken","MistAPIURI","MistOrgID","MistVariablesSave","MistVariablesToSave")
$ModuleFolder = $MyInvocation.MyCommand.Path -replace "PowerMist\.psm1"

$MistCountries = @{
    "default"="GB"
}

$MistTimeZones = @{
    "default"="Etc/GMT"
}



Function Get-MistSavedAPIURI
{
<#
.SYNOPSIS
Gets the current used APIUri for the mist module
.DESCRIPTION
Outputs the module variable that stores the URI used for API Calls to Mist
#>

    $MistAPIURI
}

Function Get-MistSavedSession
{
<#
.SYNOPSIS
Gets the current used WebSession for the mist module
.DESCRIPTION
Outputs the module variable that stores the WebSession used for API Calls to Mist
#>   
    $MistSession
}

Function Get-MistSavedAPIToken
{
<#
.SYNOPSIS
Gets the current used APIToken for the mist module
.DESCRIPTION
Outputs the module variable that stores the APIToken used for API Calls to Mist
#>   
    $MistAPIToken
}

Function Get-MistSavedOrgID
{
<#
.SYNOPSIS
Gets the current used orgid for the mist module
.DESCRIPTION
Outputs the module variable that stores the currently selected orgid used for organisation specific api calls
#>   
    $MistOrgID
}

Function Get-MistSavedUserCreds
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

Function Set-MistSavedAPIURI
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

Function Restart-MistSession
{
<#
.SYNOPSIS
Refreshes the Web session to use for API Calls to Mist
.DESCRIPTION
Refreshes or creates a new API Session
.EXAMPLE
Restart-MistSession -token
#>
    param
    (
        [switch]
        $token,
        [switch]
        $credentials
    )

    if (($token) -or ($MistAPIToken -ne $null))
    {
        Invoke-MistLogin -APIToken $MistAPIToken
    }
    elseif ($credentials -or ($MistUserCreds -ne $null))
    {
        Invoke-MistLogin -AP
    }
    else
    {
        throw "No possible authentication process designated, please check your credentials and try again"
    }
}

Function Set-MistSavedAPIToken
{
    param
    (
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]
        $NewMistAPIToken
    )
    set-variable -scope Global -name MistAPIToken -value $NewMistAPIToken
}

Function Set-MistSavedAPITokenFromPath
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]
        $NewMistAPITokenPath
    )

    $NewMistAPIToken = Import-MistAPIToken $NewMistAPITokenPath

    set-variable -scope Global -name MistAPIToken -value $NewMistAPIToken
}

Function Set-MistSavedOrgID
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $NewMistOrgID
    )
    set-variable -scope Global -name MistOrgID -value $NewMistOrgID
}

Function Set-MistSavedUserCreds
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









## This is a bad way of storing the Token, I will be replacing this



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








## Load any saved variables

Invoke-MistVariableLoad

try
{
    $MistAPIToken = Get-Variable -Scope Global -Name MistAPIToken -Value -ErrorAction SilentlyContinue
    $MistUserCreds = Get-Variable -Scope Global -Name MistUserCreds -Value -ErrorAction SilentlyContinue
}
catch
{

}

if ($MistAPIToken -ne $null)
{
    Write-Verbose $MistAPIToken.id
    Write-Verbose $MistAPIToken.key
    Invoke-MistLogin -APIToken $MistAPIToken
}
elseif ($MistUserCreds -ne $null)
{
    Write-Verbose $MistUserCreds
    Invoke-MistLogin -Credentials $MistUserCreds
}
else
{
    Write-Debug $MistAPIToken
    Write-Debug $MistUserCreds
    Write-Debug "No credentials stored"
}