

<#  
.SYNOPSIS  
    Looks at domain Top and all OUs and reports who can edit gPLinks. Exclusing domain admins and named lists  
.DESCRIPTION  
    -Exclude is a -like *String* search, so don't use short strings.
.NOTES  
    File Name  : OUAcls.ps1  
    Author     : Mark R. Gamache  - mark@markgamache.com  - @markGamacheNerd  
    Requires   : UNK.  Computers I guess  
.LINKS
    Use BloodHound, it's better https://github.com/BloodHoundAD/BloodHound     

     
#>
param(
    [parameter(Mandatory=$true)]
    [string] $DomainDNS,

    [parameter(Mandatory=$false)]
    [string[]] $Exclude = @()
     
)

$SIDCache = @{}
$PrinCache = @{}

function Spew-ACL{
    Param(
  	
       [Parameter(Mandatory=$True)]
       [string]$objectDN
    )

    if($bLocalDomain)
    {
        $baseACL = Get-Acl "ad:\$objectDN"
    }
    else
    {
        $baseACL = Get-Acl "RemAD:\$objectDN"
    }


    foreach($ace in $baseACL.Access)
                                                                                                                                                                                                                            {
    $tempObj = [pscustomobject] @{ActiveDirectoryRights="";
                                    ActiveDirectoryRightsV=""; 
                                    InheritanceType="";
                                    ObjectType="";
                                    InheritedObjectType="";
                                    ObjectFlags="";
                                    IdentityReference="";
                                    IsInherited="";
                                    InheritanceFlags="";
                                    PropagationFlags="";
                                    AccessControlType=""
                                }


    #$ace.Access
    $tempObj.AccessControlType = $ace.AccessControlType
    $tempObj.ActiveDirectoryRightsV = [int] $ace.ActiveDirectoryRights
    $tempObj.ActiveDirectoryRights = $ace.ActiveDirectoryRights
    $tempObj.InheritanceType = $ace.InheritanceType
    $tempObj.ObjectType = $ace.ObjectType
    $tempObj.InheritedObjectType = $ace.InheritedObjectType
    $tempObj.ObjectFlags = $ace.ObjectFlags
    $tempObj.IdentityReference = $ace.IdentityReference
    $tempObj.IsInherited = $ace.IsInherited
    $tempObj.InheritanceFlags = $ace.InheritanceFlags
    $tempObj.PropagationFlags = $ace.PropagationFlags



    if($ace.ActiveDirectoryRights -band 8 -and $ace.ActiveDirectoryRights -lt 983551)
    {
        echo "Self"
    }

    if($ace.ActiveDirectoryRights -band 256 )
    {
        if($ace.ObjectType -ne "00000000-0000-0000-0000-000000000000")
        {
            $tempObj.ObjectType = $reverseExtendedrightsmap[$ace.ObjectType]
        }
    }
    else
    {
        
        if($ace.ObjectType -ne "00000000-0000-0000-0000-000000000000")
        {
            try
            {
                $tempObj.ObjectType = $reverseGuidmap[$ace.ObjectType]
                if($tempObj.ObjectType -eq $null)
                {
                    $tempObj.ObjectType = $reverseExtendedrightsmap[$ace.ObjectType]
                }
            }
            catch
            {
                write-host " "
            }
        }
    }

    if($ace.InheritedObjectType -ne "00000000-0000-0000-0000-000000000000")
    {
        $tempObj.InheritedObjectType = $reverseGuidmap[$ace.InheritedObjectType]
    }

    $tempObj

    $tempObj = $null

    }

}


function getMembers ([string] $Private:accnt)
{
    $Private:thing = $null


    if($Private:accnt.StartsWith("S-1"))
    {
        #odd use case with crazy SID
        $Private:Ob = [pscustomobject] @{DistinguishedName = $Private:accnt}
        return $Private:Ob   
    }


    if($PrinCache.ContainsKey($Private:accnt))
    {
        return $PrinCache[$Private:accnt]
    }
    else
    {

        $Private:domm = $Private:accnt.Split('\')[0]

        $Private:ac = $Private:accnt.Split('\')[1]

    

        try
        {
            $Private:thing = Get-ADUser $Private:ac -ErrorAction SilentlyContinue -Server "$($doms[$Private:domm])"
        }
        catch
        {
            Write-Verbose "User get fail for $Private:ac . Dont worry, this may be a group"
        }
        if($Private:thing -eq $null)
        {
            #must be a group. Enum!
            try
            {
                $Private:dddd = $null
                $Private:dddd =  Get-ADGroupMember -Recursive $Private:ac -Server "$($doms[$Private:domm])"
                $PrinCache.Add($Private:accnt, $Private:dddd)
                return $Private:dddd
            }
            catch
            {
                $mess = $Error[0].Exception.Message
                if($mess -eq "The operation being requested was not performed because the user has not been authenticated")
                {
                    $Private:stuffs = (Get-ADObject -LDAPFilter "(samaccountname=$Private:ac)" -Properties member -Server "$($doms[$Private:domm])").member
                    $Private:resovles = @()
                    foreach($Private:mmm in $Private:stuffs)
                    {
                        if($Private:mmm -like "*,CN=ForeignSecurityPrincipals,*")
                        {
                            $Private:pie = $Private:mmm.SubString($Private:mmm.IndexOf("=") + 1)
                            $Private:pie = $Private:pie.SubString(0, $Private:pie.IndexOf(",") )
                            try
                            {
                                if($SIDCache.ContainsKey($Private:pie))
                                {
                                    $Private:resovles +=  getMembers $SIDCache[$Private:pie]
                                }
                                else
                                {
                                    $Private:accttt  = New-Object System.Security.Principal.SecurityIdentifier($Private:pie)
                                    $Private:objUser = $Private:accttt.Translate( [System.Security.Principal.NTAccount])
                                    $SIDCache.Add($Private:pie, $Private:objUser.Value)
                                    $Private:resovles +=  getMembers $Private:objUser.Value
                                    #Write-Host $Private:pie
                                }
                            }
                            catch
                            {
                                $Private:newy = [pscustomobject] @{DistinguishedName = $Private:pie}
                                #$SIDCache.Add($Private:pie, $Private:newy)
                                $Private:resovles += $Private:newy
                                $Private:newy = $null
                                #Write-Host " " 
                            }
                        }
                        else
                        {
                            $Private:newy = [pscustomobject] @{DistinguishedName = $Private:mmm}
                            $Private:resovles += $Private:newy
                            $Private:newy = $null
                        
                        }
                    }

                    $PrinCache.Add($Private:accnt, $Private:resovles)
                    return $Private:resovles

                
                }
                else
                {
                    Write-Verbose  "get group fail for $Private:domm \ $Private:accnt investigate!"
                    Write-Host $mess
                }
            }
        }
        else
        {
            #is user return it
            $PrinCache.Add($Private:accnt, $Private:thing)
            return $Private:thing
        }
    }

}


function bIgnoreACE([string] $Private:ref)
{
    if($Private:ref.StartsWith("O:"))
    {
        return $true
    }
    foreach($ig in $excludeList)
    {
        if($Private:ref -like "*$ig*")
        {
            return $true
        } 

    }
    
    return $false
    
}


function setupMaps
{
                                                                          
    #Get a reference to the RootDSE of the current domain
    $rootdse = Get-ADRootDSE -Server $DomainDNS
    #Get a reference to the current domain
    $domain = Get-ADDomain $DomainDNS

    #Create a hashtable to store the GUID value of each schema class and attribute
    $guidmap = @{}
    Get-ADObject -Server $DomainDNS -SearchBase "$($rootdse.SchemaNamingContext)" -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | % {$guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}

    $reverseGuidmap = @{}
    Get-ADObject -Server $DomainDNS -SearchBase "$($rootdse.SchemaNamingContext)" -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | % {$reverseGuidmap[[System.GUID]$_.schemaIDGUID]=$_.lDAPDisplayName}


    #Create a hashtable to store the GUID value of each extended right in the forest
    $extendedrightsmap = @{}
    Get-ADObject -Server $DomainDNS -SearchBase "$($rootdse.ConfigurationNamingContext)" -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | % {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}


    $reverseExtendedrightsmap = @{}
    Get-ADObject -Server $DomainDNS -SearchBase "$($rootdse.ConfigurationNamingContext)" -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | % {$reverseExtendedrightsmap[[System.GUID]$_.rightsGuid]=$_.displayName}


    return $guidmap, $reverseGuidmap, $extendedrightsmap, $reverseExtendedrightsmap
}

#pain for looking at a foreign domain
if($env:USERDNSDOMAIN -ne $DomainDNS)
{
    # new SPDrive for foriegn domain. get and set ACL use a PSdrive with no server paramer
    New-PSDrive -Name RemAD -PSProvider ActiveDirectory -Server $DomainDNS -Scope Global -root "//RootDSE/"
    $bLocalDomain = $false
    Write-Warning "You are testing across a trust boundry, this will cause failures for non-transitive trusts."
}
else
{
    $bLocalDomain = $true
}

Write-Warning "This tool is neat, but to get the full picture, you need to combine it with other paths to failure. You should really using https://github.com/BloodHoundAD/BloodHound "

Write-Verbose "Getting AD schema data"

#get the attribute name map and rights sets map
$maps = setupMaps
$guidmap = $maps[0]
$reverseGuidmap = $maps[1]
$extendedrightsmap = $maps[2]
$reverseExtendedrightsmap = $maps[3]

$allOUs = $null




$excludeList = @()
$excludeList += "BUILTIN\Administrators"
$excludeList += "Domain Admins"

foreach($ex in $Exclude)
{
    $excludeList += $ex
}

Write-Verbose "Getting AD Trusts"
#map of domains with NBN and dns name  (Get-ADDomain).NetBIOSName
$doms = @{}
$thisDom = Get-ADDomain $DomainDNS
$doms.Add($thisDom.NetBIOSName, $thisDom.DNSRoot)
$trusts = Get-ADTrust -Filter * -Server $DomainDNS

foreach($tr in $trusts)
{
    $NBN = $null
    try
    {
        $NBN =  (Get-ADDomain "$($tr.Target)")
        if($NBN -ne $null)
        {
            if(! $doms.Contains($NBN.NetBIOSName))
            {
                $doms.Add($NBN.NetBIOSName, $tr.Target) 
            }
        }
    }
    catch
    {
        if($Error[0].Exception.Message -eq "The server has rejected the client credentials.")
        {
            Write-Warning "Can't get info on domain $($tr.Target)"
            Write-Warning "This may be due to non-transitive tursts, or one way trusts"
        }
        else
        {
            $Error[0]
            Write-Warning "$($tr.Target): This may be due to non-transitive tursts, or one way trusts"
        }
    }



}

Write-Warning "Getting OUs"

$allOUs =  Get-ADOrganizationalUnit -Filter * -Server $DomainDNS
$ousWithData = @()

Write-Verbose "Processing OUs"

foreach($ou in $allOUs)
{
    Write-Verbose $ou.DistinguishedName
   
    $theACLS = $null
    $theACLS = Spew-ACL "$($ou.DistinguishedName)"

    if($bLocalDomain)
    {
        $own = Get-Acl "ad:\$($ou.DistinguishedName)"
    }
    else
    {
        $own = Get-Acl "RemAD:\$($ou.DistinguishedName)"
    }

    $theOwn = $null
    #the object taht we array and return later
    

    $OUdats = [PSCustomObject]@{
        DN = $($ou.DistinguishedName)
        Writers = @{}
        Owned = @()

    }


    if(!(bIgnoreACE "$($own.Owner)"))
    {
       
               
        $theOwn =  getMembers "$($own.Owner)"
        foreach($mem in $theOwn)
        {
            #use HT
            if(! $OUdats.Writers.Contains($mem.distinguishedName))
            {
                $OUdats.Writers.Add( $mem.distinguishedName, $mem)
            }
            
        }
        $theOwn =  $null
        $mem = $null
        #$own.Owner
    }


    foreach($ace in $theACLS)
    {
        
        $thems = $null
        if($ace.ObjectType -eq "gplink" -and $ace.ActiveDirectoryRights -like "*WriteProperty*" )
        {
            if(!(bIgnoreACE "$($ace.IdentityReference.ToString())"))
            {
                #Write-Warning "$($ou.DistinguishedName)"
                $thems = $null

                $thems =  getMembers "$($ace.IdentityReference.ToString())"
                foreach($mem in $thems)
                {
                    try
                    {
                        #use HT
                        if(! $OUdats.Writers.Contains($mem.distinguishedName))
                        {
                            $OUdats.Writers.Add( $mem.distinguishedName, $mem)
                        }
                 
                    }
                    catch
                    {
                        #cross forest odd
                        if(! $OUdats.Writers.Contains($mem.name))
                        {
                            $OUdats.Writers.Add( $mem.name, $mem)
                        }
                  
                    }
                }
               
                $thems = $null
                $mem = $null
                #$ace
            }
        }
        elseif($ace.ActiveDirectoryRights -like "GenericAll" -and !($ace.IdentityReference.ToString() -ne "NT AUTHORITY\SYSTEM" -or $ace.IdentityReference.ToString() -notlike "*domain admins"  ))
        {
            if(!(bIgnoreACE "$($ace.IdentityReference.ToString())"))
            {
               # Write-Warning "$($ou.DistinguishedName)"
                $thems =  getMembers "$($ace.IdentityReference.ToString())"
                foreach($mem in $thems)
                {
                        #use HT
                    if(! $OUdats.Writers.Contains($mem.distinguishedName))
                    {
                        $OUdats.Writers.Add( $mem.distinguishedName, $mem)
                    }
                   
                }
               
                $thems = $null
                $mem = $null
                #$ace
            }
        }
        elseif($ace.ActiveDirectoryRights -like "*WriteOwner*" -or $ace.ActiveDirectoryRights -like "*WriteDacl*" -and !($ace.IdentityReference.ToString() -ne "NT AUTHORITY\SYSTEM" -or $ace.IdentityReference.ToString() -notlike "*domain admins"  ))
        {
            if(!(bIgnoreACE "$($ace.IdentityReference.ToString())"))
            {
                #Write-Warning "$($ou.DistinguishedName)"
                $thems =  getMembers "$($ace.IdentityReference.ToString())"
                foreach($mem in $thems)
                {
                        #use HT
                    if(! $OUdats.Writers.Contains($mem.distinguishedName))
                    {
                        $OUdats.Writers.Add( $mem.distinguishedName, $mem)
                    }
                
                }
               
                $thems = $null
                $mem = $null
                #$ace
            }
        }
        else
        {
           # $ace 
           # write-host " "
        }
    }

   #echo "`r`n "

   if($OUdats.Writers.Count -gt 0)
   {
        #get what's under

        $ownedObjs = $null
        $ownedObjs = Get-ADObject -SearchBase $ou.DistinguishedName -LDAPFilter "(objectclass=user)" -Server $DomainDNS
        $OUdats.Owned += $ownedObjs
        $ousWithData += $OUdats
   }
   else
   {
        #echo "clean OU" 

   }
}

Remove-PSDrive -Name RemAD 
$ousWithData
