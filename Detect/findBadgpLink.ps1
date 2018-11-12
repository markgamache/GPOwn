<#  
.SYNOPSIS  
    Looks at domain Top and all OUs and reports if any gpLinks have been hijacked to non-DCs  
.DESCRIPTION  
    What I just said 
.NOTES  
    File Name  : findBadgpLink.ps1  
    Author     : Mark R. Gamache  - mark@markgamache.com  - @markGamacheNerd  
    Requires   : UNK.  Computers I guess  
     


#>

Param (
	[parameter(Mandatory = $True)]
	$DomainDNS
		
)

function isLinkDnTrusted([string[]]$Private:trustDNs, [string] $Private:theDN)
{
    
    foreach($Private:otr in $Private:trustDNs)
    {
        if($Private:otr -ceq $Private:theDN)
        {
            return $true
        }
    }
    return $false
    
}

if($env:USERDNSDOMAIN -eq $DomainDNS)
{
}
else
{
    Write-Warning "You are running this test using an out of domain account. For best results use an account you the domain you are scanning.`r`nNon-Transitive trusts may cause holes in the data."
}

Write-Host "Enumerating trusts to rule out cross domain and cross forest linking.`r`nThere may be SSPI errors for one way trusts" 

#we need the DNs of any domain we might link a GPO to.
$trusts = $null
$trustDNs = @()
$trustDNs += ((Get-ADDomain $DomainDNS).DistinguishedName).ToLower()
$trusts = [string[]](Get-ADTrust -Filter * -Server $DomainDNS).Target 
foreach($tr in $trusts)
{
    try
    {
        $trustDNs += ((Get-ADDomain $tr ).DistinguishedName).ToLower()
    }
    catch
    {
        if($Error[0].Exception.Message -eq "A call to SSPI failed, see inner exception.")
        {
            
        }
        else
        {
            Write-Error -Exception $Error[0].Exception
        }
    }
}


Write-Host "Getting all gpLinks"
$linkObjects = $null
$linkObjects = Get-ADObject -LDAPFilter "(gplink=*)" -Properties gpLink -Server $DomainDNS

$bBadFound = $false

Write-Host "Evaluating all gpLink LDAP URLs"
foreach($lo in $linkObjects)
{
    if($lo.gpLink -eq " ")
    {
        continue
    }
    $lparts = $null
    $lparts = $lo.gplink -split ']'
    foreach($part in $lparts)
    {
        if($part -eq "")
        {
            continue
        }
        #$place = 
        $part = $part.ToLower()
        $part = $part.SubString($part.IndexOf(",dc=") + 1)
        try
        {
            $part = $part.SubString(0,$part.IndexOf(";"))
        }
        catch
        {
            $Error[0]
        }
       
        if( isLinkDnTrusted $trustDNs $part)
        {
            #
        }
        else
        {
            #freak
            Write-Warning "The object $($lo.DistinguishedName) has a link to $($part), which is not a valid AD GPO link.`r`n$($lo.gpLink)"
            Write-Host " "
            $bBadFound = $True

        }

    }


}

if($bBadFound)
{
    Write-Warning "Look above, scary stuff found"
}
else
{
    Write-Host "All clear.  No bad found"
}
