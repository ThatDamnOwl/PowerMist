$ModuleFolder = $MyInvocation.MyCommand.Path -replace "PowerMist_Sites\.psm1"

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

Function Get-MistSiteSetting
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [String[]]
        $Settings,
        [switch]
        $All
    )
    $Return = Invoke-RestMethod -uri "$MistAPIURI/sites/$SiteID/setting"  -WebSession $MistSession -Method get

    if ($All)
    {

    }
    else
    {
        $Members = $Return | Get-Member

        foreach ($Member in $Members)
        {
            if ($Member.name -notin $Settings)
            {
                $Return.PSObject.Properties.Remove($Member.Name)
            }
        }
    }

    return $Return

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
    return Get-PageinatedList -ListURI "$MistAPIURI/sites/$SiteID/wlans/derived?resolve=$Resolve" -WebSession $MistSession
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

Function Get-MistSiteClients
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Get-PageinatedList $MistSession "$MistAPIURI/sites/$SiteID/stats/clients" -WebSession $MistSession
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

