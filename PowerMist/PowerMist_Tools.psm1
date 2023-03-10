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