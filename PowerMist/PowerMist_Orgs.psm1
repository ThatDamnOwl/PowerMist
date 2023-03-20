$ModuleFolder = $MyInvocation.MyCommand.Path -replace "PowerMist_Orgs\.psm1"

Function Get-MistOrganizations
{
    param
    (

    )
    return (Get-MistUserInfo $MistSession).privileges | where {$_.Scope -eq "org"}
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

Function Get-MistOrgRFTemplates
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

    Get-PageinatedList -ListUri "$MistAPIURI/orgs/$MistOrgID/psks" -PageSize 100 -WebSession $MistSession
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
    Get-PageinatedList -ListURI "$MistAPIURI/orgs/$MistOrgID/sites" -PageSize 100 -WebSession $MistSession
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

    $AllWaps = Get-PageinatedList -ListURI $ListURI -PageSize 100 -WebSession $MistSession

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

    $Edges = Get-PageinatedList -ListURI $ListURI -PageSize 100 -WebSession $MistSession

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

    $Hyphenated += Get-SeperatedMAC $DisconnectWAP "-"

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

Function Get-MistDeviceManagementURI
{
    param 
    (
        $MistDevice
    )
    return "https://manage.mist.com/admin/?org_id=$($MistDevice.org_id)#!$($MistDevice.type)/detail/$($MistDevice.id)/$($MistDevice.site_id)"
}