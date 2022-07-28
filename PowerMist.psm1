## Constants
#ToDo Change all hashtables to lookups from API for more flexibility
# Mist API Endpoint
#Forcing TLS1.2 otherwise requests on certain machines will fail
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$APIURI = "https://api.mist.com/api/v1"

$Countries = @{
    "default"="GB"
}

$TimeZones = @{
    "default"="Etc/GMT"
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
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session,
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

        $WebRequest = Invoke-WebRequest -uri "$($ListURI)$($Operator)limit=$PageSize&page=$Page" -WebSession $Session -ContentType "application\json"
        
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

Function Get-MistSession
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

    $LoginDeets = Invoke-WebRequest -uri "$APIURI/login" -Method POST -Body $LoginJson -ContentType application/json -SessionVariable 'Session'
    
    $Session.Headers.add("X-CSRFTOKEN", ((($Session.Cookies.GetCookieHeader("$APIURI") -split ";")[0] -split "=")[1]))

    $UserInfo = Get-MistUserInfo $Session

    if ($UserInfo.two_factor_required)
    {
        Write-Host "2FA is enabled for this account, please enter your 2FA key"
        $2FA = read-host

        $2FAJson = "{""two_factor"": ""$2FA""}"

        $LoginDeets = Invoke-WebRequest -uri "$APIURI/login/two_factor" -Method POST -Body $2FAJson -ContentType application/json -WebSession $Session
        $Session.headers.'X-CSRFTOKEN' = ((($Session.Cookies.GetCookieHeader("$APIURI") -split ";")[0] -split "=")[1])
    }
    else {
        
    }
    return $Session
}

Function Get-MistUserInfo
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    return Invoke-RestMethod -uri "$APIURI/self"  -WebSession $Session -Method get
}

Function Get-MistSite
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Invoke-RestMethod -uri "$APIURI/sites/$SiteID"  -WebSession $Session -Method get
}

Function Get-MistSiteSettings
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Invoke-RestMethod -uri "$APIURI/sites/$SiteID/setting"  -WebSession $Session -Method get
}

Function Set-MistSiteWlan
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
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
    return Invoke-WebRequest -uri "$APIURI/sites/$SiteID/wlans/$WLANID" -WebSession $Session -Method Put -Body ($WLANSettings | convertto-json) -ContentType "application/json"
}

Function Set-MistSiteSettings
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
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
            Write-Verbose "$($Property.name) is not an allowed field, removing from the settings"
            $SiteSettings.PSObject.Properties.remove($Property.name)
        }
    }
    #$SiteSettings
    return Invoke-WebRequest -uri "$APIURI/sites/$SiteID/setting" -WebSession $Session -Method Put -Body ($SiteSettings | convertto-json) -ContentType "application/json"
}

Function Get-MistSiteWlans
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID,
        [Parameter(Mandatory=$false)]
        [switch]
        $Resolve
    )
    return Get-PageinatedList -ListURI "$APIURI/sites/$SiteID/wlans/derived?resolve=$Resolve" -Session $Session
}

Function Get-MistSiteGroups
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    return Invoke-RestMethod -uri "$APIURI/sites/$SiteID/wlans"  -WebSession $Session -Method get
}

Function Get-MistAPISession
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $APIKey
    )
    $LoginDeets = Invoke-RestMethod -uri "$APIURI/self" -Headers @{"Authorization"="Token $($APIKey["Key"])"} -SessionVariable Session -Method get
    return $Session
}

Function Get-MistOrganizations
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session
    )
    return (Get-MistUserInfo $Session).privileges | where {$_.Scope -eq "org"}
}

Function Get-MistOrgWlans
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/wlans" -WebSession $Session
}

Function Get-MistOrgTemplate
{
        param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $TemplateID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/templates/$TemplateID" -WebSession $Session
}

Function Get-MistOrgWlan
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgWlanID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/wlans/$OrgWlanID" -WebSession $Session
}

Function Get-MistOrgTemplates
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/templates" -WebSession $Session
}

Function Get-MistOrgGroup
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $GroupID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/sitegroups/$GroupID" -WebSession $Session
}

Function Get-MistRFTemplates
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/rftemplates" -WebSession $Session
}

Function Get-MistGroupWlans
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $GroupID
    )
    $Wlans = @() 
    $Templates = Get-MistOrgTemplates $Session $OrgID 
    $OrgWlans = Get-MistOrgWlans $Session $OrgID
    
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
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    Get-PageinatedList -ListURI "$APIURI/orgs/$OrgID/sites" -Session $Session -PageSize 100
}

Function Get-MistSiteGroups
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/sitegroups" -WebSession $Session
}

Function Get-MistInventory
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    Invoke-RestMethod -uri "$APIURI/orgs/$OrgID/inventory" -WebSession $Session
}

Function Get-MistAPIKeys
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $APIKeyPath
    )
    Invoke-RestMethod -uri "$APIURI/self/apitokens" -WebSession $Session
}

Function New-MistAPIKey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $APIKeyPath
    )
    $TempAPIKey = Invoke-WebRequest -uri "$APIURI/self/apitokens" -WebSession $Session -Method Post -Body $null -ContentType "application/json"
    
    $APIKey = @{"ID" = ""; "Key" = ""}
    $ignore = ($TempAPIKey.Content -match """id"":""[^""]*""")
    $APIKey["ID"] = ($Matches[0] -split ":")[1] -replace """"
    $ignore = ($TempAPIKey.Content -match """key"":""[^""]*""")
    $APIKey["Key"] = ($Matches[0] -split ":")[1] -replace """"

    return $APIKey
}

Function Get-MistDeviceStats
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )

    $ListURI = "$APIURI/orgs/$OrgID/stats/devices"

    $AllWaps = Get-PageinatedList -Session $Session -ListURI $ListURI -PageSize 100

    return $AllWaps | where {$_.ip.Length -gt 0}
}

Function Get-MistOrgEdges
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )

    $ListURI = "$APIURI/orgs/$OrgID/mxedges"

    $Edges = Get-PageinatedList -Session $Session -ListURI $ListURI -PageSize 100

    return $Edges
}

Function New-MistSite 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,
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
        $Lat = "51.477934", 
        [Parameter(Mandatory=$false)]
        [String]
        $Lng = "-0.001467", 
        [Parameter(Mandatory=$false)]
        [String]
        $Address = "Greenwich, London SE10 8XJ, United Kingdom", 
        [Parameter(Mandatory=$false)]
        [String]
        $RFTemplate, 
        [Parameter(Mandatory=$false)]
        [Object[]]
        $SiteGroups
    )
    
    $SiteProperties = "{
    ""name"": ""$SiteName"",
    ""timezone"": ""$TimeZone"",
    ""country_code"": ""$Country"",
    ""rftemplate_id"": ""$RFTemplate"",
    ""secpolicy_id"": """",
    ""alarmtemplate_id"": """",
    ""latlng"": { ""lat"": $lat, ""lng"": $lng },
    ""sitegroup_ids"": $(if ($SiteGroups -ne $null) {Get-JSONArray $SiteGroups} else {"[ ]"}),
    ""address"": ""$Address""
}"
    Invoke-WebRequest -uri "$APIURI/orgs/$OrgID/sites" -WebSession $Session -Method Post -Body $SiteProperties -ContentType "application/json"
}

Function Reset-MistOrgEdgePorts 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,  
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
    ## Write-Host "$APIURI/orgs/$OrgID/mxedges/$MEID/services/tunterm/bounce_port"
    ## Write-Host "$BouncePorts"
    ## Write-Host $Ports
    Invoke-WebRequest -uri "$APIURI/orgs/$OrgID/mxedges/$MEID/services/tunterm/bounce_port" -WebSession $Session -Method Post -Body $Ports -ContentType "application/json"
}

Function Get-MistSiteClients
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    return Get-PageinatedList $Session "$APIURI/sites/$SiteID/stats/clients"
}

Function Get-MistSiteMap
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $MapID
    )
    #"$APIURI/api/v1/sites/$SiteID/maps" 
    return Invoke-RestMethod -uri "$APIURI/sites/$SiteID/maps/$MapID" -WebSession $Session
}

Function Get-MistSiteMaps
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID
    )
    #"$APIURI/api/v1/sites/$SiteID/maps" 
    return Invoke-RestMethod -uri "$APIURI/sites/$SiteID/maps" -WebSession $Session
}

Function Get-MistSiteDevice
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $SiteID, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $DeviceID
    )
    #"$APIURI/api/v1/sites/$SiteID/maps" 
    return Invoke-RestMethod -uri "$APIURI/sites/$SiteID/devices/$DeviceID" -WebSession $Session
}

Function Disconnect-MistWAPfromEdge 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,  
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

    Write-Host "$APIURI/orgs/$OrgID/mxedges/$MEID/services/tunterm/disconnect_aps"

    Invoke-WebRequest -uri "$APIURI/orgs/$OrgID/mxedges/$MEID/services/tunterm/disconnect_aps" -WebSession $Session -Method Post -Body $WAPArr -ContentType "application/json"
}

Function Disconnect-MistWAPsfromEdgeAtRandom
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID,  
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

    Write-Host "$APIURI/orgs/$OrgID/mxedges/$MEID/services/tunterm/disconnect_aps"

    Invoke-WebRequest -uri "$APIURI/orgs/$OrgID/mxedges/$MEID/services/tunterm/disconnect_aps" -WebSession $Session -Method Post -Body $WAPArr -ContentType "application/json"
}

Function Import-MistSites
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $Session, 
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\w{8}-\w{4}-\w{4}-\w{4}-\w{12}")]
        [String]
        $OrgID
    )
    $Sites = import-csv -LiteralPath $CSV
    $ExistingSites = Get-AllSites $Session
    foreach ($Site in $Sites)
    {
        $SiteName = "$($Site.'Site Code') - $($Site.'Branch Name')"

        if (($ExistingSites | where {$_.name -match $Site.'Site Code'}) -eq $null)
        {
            Write-Host "$SiteName Doesn't exist"
            New-Site $Session $SiteName 
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