[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

$ModuleFolder = $MyInvocation.MyCommand.Path -replace "PowerMist_Auth\.psm1"

Import-module "$ModuleFolder\PowerMist_Tools.psm1" -force

Function Invoke-MistLogin
{
    param
    (
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PsCredential]
        $Credentials,
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]
        $APIToken
    )

    if (-not $MistAPIToken)
    {
        try
        {
            $MistAPIToken = Get-Variable -Scope Global -Name MistAPIToken -Value
        }
        catch
        {

        }
    }

    if (($Credentials -eq $null) -and ($APIToken -eq $null))
    {
        $Credentials = Get-Credential
    }

    if ($Credentials)
    {
        $LoginJson = "{""email"": ""$($Credentials.UserName)"", ""password"": ""$($Credentials.GetNetworkCredential().Password)""}"

        $LoginDeets = Invoke-WebRequest -uri "$MistAPIURI/login" -Method POST -Body $LoginJson -ContentType application/json -SessionVariable 'Session'
        
        $Session.Headers.add("X-CSRFTOKEN", ((($MistSession.Cookies.GetCookieHeader("$MistAPIURI") -split ";")[0] -split "=")[1]))

        $UserInfo = Get-MistUserInfo $MistSession

        if ($UserInfo.two_factor_required)
        {
            Write-Host "2FA is enabled for this account, please enter your 2FA Token"
            $2FA = read-host

            $2FAJson = "{""two_factor"": ""$2FA""}"

            $LoginDeets = Invoke-WebRequest -uri "$MistAPIURI/login/two_factor" -Method POST -Body $2FAJson -ContentType application/json -WebSession $MistSession
            $Session.headers.'X-CSRFTOKEN' = ((($MistSession.Cookies.GetCookieHeader("$MistAPIURI") -split ";")[0] -split "=")[1])
        }
        else {
            
        }
    }
    else
    {
        Write-Debug "APIToken Provided - $($APIToken -eq $null)"
        Write-Debug "MistAPIToken Provided - $($MistAPIToken -eq $null)"
        Write-Debug "Credentials provided - $($Credentials -eq $null)"

        if (($APIToken -eq $null) -and ($MistAPIToken -ne $null))
        {
            $APIToken = $MistAPIToken
        }
        elseif ($APIToken -ne $null)
        {

        }
        else
        {
            throw "No API Token or Credentials provided and no API Token stored, please provide an API Token or Credentials"
        }

        if (-not $MistAPIToken)
        {
            set-variable -scope Global -name MistAPIToken -Value $APIToken
        }

        $LoginDeets = Invoke-RestMethod -uri "$MistAPIURI/self" -Headers @{"Authorization"="Token $($APIToken["Key"])"} -SessionVariable Session -Method get
    }

    set-variable -Scope Global -Name MistSession -Value $Session
}

Function Invoke-MistLogout
{
    param
    (

    )

    $Return = Invoke-WebRequest -uri "$MistAPIURI/logout" -Method POST -ContentType application/json -WebSession $MistSession

    return ($Return.statuscode -eq 200)
}

Function Get-MistUserInfo
{
    param
    (

    )
    return Invoke-RestMethod -uri "$MistAPIURI/self"  -WebSession $MistSession -Method get
}

Function Get-MistLoginStatus
{
    param
    (

    )

    try
    {
        $UserInfo = Get-MistUserInfo
    }
    catch
    {

    }

    return ($UserInfo -ne $null)
}

Function Get-MistUserAuditLogs
{
    param
    (   
        [Parameter(Mandatory=$true)]
        $StartDate,
        [Parameter(Mandatory=$true)]
        $EndDate
    )

    $EDStart = Get-Date $StartDate.ToUniversalTime() -uformat "%s"
    $EDEnd = Get-Date $EndDate.ToUniversalTime() -uformat "%s"

    $EDStartFloor = [Math]::Floor([decimal]$EDStart)
    $EDEndFloor = [Math]::Floor([decimal]$EDEnd)

    Get-PageinatedList -listuri "$MistAPIURI/self/logs?start=$EDStartFloor&end=$EDEndFloor"
}

Function Get-MistAPIToken
{
    param
    (
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]
        $APIToken,
        [switch]
        $all
    )
    
    $APITokens = Invoke-RestMethod -uri "$MistAPIURI/self/apitokens" -WebSession $MistSession

    if (-not $all)
    {
        return ($APITokens | where {$_.id -eq $APIToken.id})
    }
}

Function New-MistAPIToken
{
    param
    (

    )
    $TempAPIToken = Invoke-WebRequest -uri "$MistAPIURI/self/apitokens" -WebSession $MistSession -Method Post -Body $null -ContentType "application/json"
    
    $APIToken = @{"ID" = ""; "Token" = ""}
    $ignore = ($TempAPIToken.Content -match """id"":""[^""]*""")
    $APIToken["ID"] = ($Matches[0] -split ":")[1] -replace """"
    $ignore = ($TempAPIToken.Content -match """Key"":""[^""]*""")
    $APIToken["Key"] = ($Matches[0] -split ":")[1] -replace """"

    return $APIToken
}

Function Remove-MistAPIToken
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $APIToken
    )

    return Invoke-WebRequest -uri "$MistAPIURI/self/apitokens/$($APIToken.id)" -WebSession $MistSession -Method Delete -ContentType "application/json"
}

Function Get-Mist2FAQRCode
{
    return Invoke-WebRequest -uri "$MistAPIURI/self/two_factor/token?by=qrcode" -WebSession $MistSession -ContentType "application/json"
}

Function Show-Mist2FAQRCode
{
    $2FAQRCode = Get-Mist2FAQRCode
    $2FAQRCode.content | set-content "$ModuleFolder\Temp.png" -encoding Byte
    $QRCodeFile = Get-Item "$ModuleFolder\Temp.png"
    $QRImage = [System.Drawing.Image]::FromFile($QRCodeFile)

    $DisplayForm = New-Object System.Windows.Forms.Form
    $DisplayForm.Text = "Please configure your Two factor auth account using the below image"
    $DisplayForm.Size = New-Object System.Drawing.Size(300,400)
    $DisplayForm.StartPosition = 'CenterScreen'

    $ButtonOK = New-Object System.Windows.Forms.Button
    $ButtonOK.Location = New-Object System.Drawing.Point(10,320)
    $ButtonOK.Size = New-Object System.Drawing.Size (75,23)
    $ButtonOK.Text = "OK"
    $ButtonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $DisplayForm.AcceptButton = $ButtonOK
    $DisplayForm.Controls.Add($ButtonOK)

    $ButtonCancel = New-Object System.Windows.Forms.Button
    $ButtonCancel.Location = New-Object System.Drawing.Point(200,320)
    $ButtonCancel.Size = New-Object System.Drawing.Size (75,23)
    $ButtonCancel.Text = "Cancel"
    $ButtonCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $DisplayForm.CancelButton = $ButtonCancel
    $DisplayForm.Controls.Add($ButtonCancel)

    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,270)
    $Label.Size = New-Object System.Drawing.Size (300,23)
    $Label.Text = "Please enter the 2FA code provided by your app after scanning the QR Code"
    $DisplayForm.Controls.Add($Label)

    $TextBox = New-Object System.Windows.Forms.TextBox
    $TextBox.Location = New-Object System.Drawing.Point(10,295)
    $TextBox.Size = New-Object System.Drawing.Size (270,23)
    $DisplayForm.Controls.Add($TextBox)

    $ImageHolder = New-Object System.Windows.Forms.PictureBox
    $ImageHolder.Location = New-Object System.Drawing.Point(10,10)
    $ImageHolder.Size = New-Object System.Drawing.Size (270,270)
    $ImageHolder.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    $ImageHolder.Image = $QRImage
    $DisplayForm.Controls.Add($ImageHolder)

    $DisplayForm.Topmost = $true

    $DisplayForm.Add_Shown({$DisplayForm.Select()})
    $result = $DisplayForm.ShowDialog()

    if ($Result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        Invoke-Mist2FAVerification $TextBox.Text
    }

    $Displayform.Dispose()
    $ButtonOK.Dispose()
    $ButtonCancel.Dispose()
    $Label.Dispose()
    $TextBox.Dispose()
    $ImageHolder.Dispose()
    $Displayform.Dispose()
    $QRImage.Dispose()
    Remove-Item $QRCodeFile
}

Function Invoke-Mist2FAVerification
{
    param
    (
        $VerificationCode
    )

    $2FAJson = "{""two_factor"": ""$VerificationCode""}"

    $Return = Invoke-WebRequest -uri "$MistAPIURI/self/two_factor/verify" -Method POST -Body $2FAJson -ContentType application/json -WebSession $MistSession

    return $Return
}

Function Confirm-MistLogin
{
    param
    (
        $EmailAddress
    )

    $CheckJson = "{""email"": ""$EmailAddress""}"

    $Return = Invoke-WebRequest -uri "$MistAPIURI/login/lookup" -Method POST -Body $CheckJson -ContentType application/json

    return ($Return.statuscode -eq 200)
}

Function Import-MistAPIToken
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $APITokenPath
    )
    $SplitPath = $APITokenPath -split "\\"
    $APIID = $SplitPath[$SplitPath.length - 1] -replace "\.txt",""
    $EncString = Get-Content $APITokenPath | ConvertTo-SecureString
    $APITokenEnc = New-Object System.Management.Automation.PsCredential($APIID, $EncString)
    $APIToken = @{"ID"=$APIID;"Token"=$APITokenEnc.GetNetworkCredential().Password.ToString()}
    $APIToken
}

Function Export-MistAPIToken
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $StoragePath,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $APIToken
    )
    $Creds = New-Object System.Management.Automation.PsCredential($APIToken["ID"], (ConvertTo-SecureString -asplaintext $APIToken["Key"] -Force))
    $Creds.Password | ConvertFrom-SecureString | Set-Content $StoragePath
}