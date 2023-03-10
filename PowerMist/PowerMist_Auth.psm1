$ModuleFolder = $MyInvocation.MyCommand.Path -replace "PowerMist_Auth\.psm1"

Import-module "$ModuleFolder\PowerMist_Tools.psm1" -force

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
    set-variable -Scope Global -Name MistSession -Value $Session
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
        set-variable -scope Global -name MistAPIKey -Value $APIKey
    }

    $LoginDeets = Invoke-RestMethod -uri "$MistAPIURI/self" -Headers @{"Authorization"="Token $($APIKey["Key"])"} -SessionVariable Session -Method get
    set-variable -Scope Global -Name MistSession -Value $Session
}

Function Get-MistUserInfo
{
    param
    (

    )
    return Invoke-RestMethod -uri "$MistAPIURI/self"  -WebSession $MistSession -Method get
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