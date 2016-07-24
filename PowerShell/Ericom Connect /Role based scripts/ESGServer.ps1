<#
.Synopsis
Deploy an ESG server as part of Ericom Connect 

.NOTES   
Name: ESGServer
Author: Erez Pasternak
Version: 1.0
DateCreated: 2016-05-29
DateUpdated: 2016-06-02
#>
param (
	[switch]$PrepareSystem = $true
)

Write-Output "AutoStart: $AutoStart"

# loads the BitsTransfer Module
Import-Module BitsTransfer
Write-Host "BitsTransfer Module is loaded"

# Settings Section
# Ericom Connect installer location 

$InstallerName = "EricomConnect.exe"
$EC_download_url_or_unc = "https://www.ericom.com/demos/"+ $InstallerName 
$EC_local_path = "C:\Windows\Temp\" + $InstallerName

# Active Directory 
$domainName = "test.local"
$AdminUser = "admin@test.local"
$AdminPassword = "admin"

# Ericom Connect Grid Setting
$GridName = ""
$LookUpHosts = ""
$MyIp = (Get-NetIPAddress -AddressFamily IPv4)[0].IPAddress 
$tenantInfo = "root"


# E-mail Settings
$To = ""
$externalFqdn = [System.Net.Dns]::GetHostByName((hostname)).HostName


# Internal Code - DO NOT CHANGE  

$ConnectConfigurationToolPath = "\Ericom Software\Ericom Connect Configuration Tool\EricomConnectConfigurationTool.exe"


$emailTemplate = "WebServer\DaaS\emails\ready.html"
$From = "daas@ericom.com"
$SMTPServer = "ericom-com.mail.protection.outlook.com"
$SMTPSUser = "daas@ericom.com"
$SMTPassword = "1qaz@Wsx#a"
$SMTPPort = 25

function Download-ESG()
{

	New-Item -Path "C:\Download-ESG" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Download-ESG  -- Start"
	
	#if we have an installer in the localpath we will use it and not download
	
	if (!(Test-Path $EC_local_path))
	{
		Write-Output "Downloading $EC_download_url_or_unc"
		Start-BitsTransfer -Source $EC_download_url_or_unc -Destination $EC_local_path -ErrorVariable DownloadError
	}
	
	if (!(Test-Path $EC_local_path))
	{
		$mail_error = "Failed to Download " + $EC_download_url_or_unc  + "<br><i>"+ $DownloadError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
		exit
	}
	Write-Output "Download-ESG  -- End"
}


function Install-ESG()
{
	New-Item -Path "C:\Install-ESG" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Ericom Connect ESG installation has been started."
	$exitCode = (Start-Process -Filepath $EC_local_path -NoNewWindow -ArgumentList "/silent /ISFeatureInstall=GRID,SG LAUNCH_CONFIG_TOOL=False" -Wait -Passthru).ExitCode
	if ($exitCode -eq 0)
	{
		Write-Output "Ericom Connect ESG has been succesfuly installed."
	}
	else
	{
		$installError = "Ericom Connect ESG could not be installed. Exit Code: " +  $exitCode
		$mail_error = "Failed to Install " + $EC_local_path  + "<br><i>"+ $installError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
		exit
	}
	Write-Output "Ericom Connect ESG installation has been endded."
}


function Config-JoinGrid()
{
	# fix code to join grid
	New-Item -Path "C:\Config-JoinGrid" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Ericom Connect JoinGrid has been started."

	$configPath = Join-Path $env:ProgramFiles -ChildPath $ConnectConfigurationToolPath.Trim()
	$args = " ConnectToExistingGrid /AdminUser $AdminUser /AdminPassword $AdminPassword /disconnect /GridName $GridName /LookUpHosts $LookUpHosts  "            

	$baseFileName = [System.IO.Path]::GetFileName($configPath);
	$folder = Split-Path $configPath;
	cd $folder;
	
    Write-Output "List of ARGS"
	Write-Output "$args"
	Write-Output "base filename"
	Write-Output "$baseFileName"
  
    $exitCode =  (Start-Process -Filepath "$baseFileName" -ArgumentList "$args" -Wait -Passthru).ExitCode
	if ($exitCode -eq 0)
	{
		Write-Output "Ericom Connect ESG has been succesfuly Joined the grid."
	}
	else
	{
		$GridConfigError = "Ericom Connect ESG could not be connected to grid. Exit Code: " +  $exitCode
		$mail_error = "Failed to Connect to  Ericom Connect Grid <br><i>"+ $GridConfigError +"</i><br>Please fix and try again." 
		SendErrorMail  -Error "$mail_error"
        exit
	}
  
	Write-Output "Ericom Connect ESG configuration has been ended."
    
}

# Remove the security settings of IE 
function Disable-IEESC
{
	$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
	$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
	Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
	Stop-Process -Name Explorer
	Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}

# Allow Multiple Sessions Per User
function AllowMultipleSessionsPerUser
{
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fSingleSessionPerUser" -Value 0
}

# Test if admin
function Test-IsAdmin() 
{
    # Get the current ID and its security principal
    $windowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsID)
 
    # Get the Admin role security principal
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    # Are we an admin role?
    if ($windowsPrincipal.IsInRole($adminRole))
    {
        $true
    }
    else
    {
        $false
    }
}

Function Show-MessageBox{

	Param(
	[Parameter(Mandatory=$True)][Alias('M')][String]$Msg,
	[Parameter(Mandatory=$False)][Alias('T')][String]$Title = "",
	[Parameter(Mandatory=$False)][Alias('OC')][Switch]$OkCancel,
	[Parameter(Mandatory=$False)][Alias('OCI')][Switch]$AbortRetryIgnore,
	[Parameter(Mandatory=$False)][Alias('YNC')][Switch]$YesNoCancel,
	[Parameter(Mandatory=$False)][Alias('YN')][Switch]$YesNo,
	[Parameter(Mandatory=$False)][Alias('RC')][Switch]$RetryCancel,
	[Parameter(Mandatory=$False)][Alias('C')][Switch]$Critical,
	[Parameter(Mandatory=$False)][Alias('Q')][Switch]$Question,
	[Parameter(Mandatory=$False)][Alias('W')][Switch]$Warning,
	[Parameter(Mandatory=$False)][Alias('I')][Switch]$Informational,
    [Parameter(Mandatory=$False)][Alias('TM')][Switch]$TopMost)

	#Set Message Box Style
	IF($OkCancel){$Type = 1}
	Elseif($AbortRetryIgnore){$Type = 2}
	Elseif($YesNoCancel){$Type = 3}
	Elseif($YesNo){$Type = 4}
	Elseif($RetryCancel){$Type = 5}
	Else{$Type = 0}
	
	#Set Message box Icon
	If($Critical){$Icon = 16}
	ElseIf($Question){$Icon = 32}
	Elseif($Warning){$Icon = 48}
	Elseif($Informational){$Icon = 64}
	Else { $Icon = 0 }
	
	#Loads the WinForm Assembly, Out-Null hides the message while loading.
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	
	If ($TopMost)
	{
		#Creates a Form to use as a parent
		$FrmMain = New-Object 'System.Windows.Forms.Form'
		$FrmMain.TopMost = $true
		
		#Display the message with input
		$Answer = [System.Windows.Forms.MessageBox]::Show($FrmMain, $MSG, $TITLE, $Type, $Icon)
		
		#Dispose of parent form
		$FrmMain.Close()
		$FrmMain.Dispose()
	}
	Else
	{
		#Display the message with input
		$Answer = [System.Windows.Forms.MessageBox]::Show($MSG , $TITLE, $Type, $Icon)			
	}

	#Return Answer
	Return $Answer
}
# Get UNC path from mapped drive
function Get-UNCFromPath
{
   Param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
    [String]
    $Path)

    if ($Path.Contains([io.path]::VolumeSeparatorChar)) 
    {
        $psdrive = Get-PSDrive -Name $Path.Substring(0, 1) -PSProvider 'FileSystem'

        # Is it a mapped drive?
        if ($psdrive.DisplayRoot) 
        {
            $Path = $Path.Replace($psdrive.Name + [io.path]::VolumeSeparatorChar, $psdrive.DisplayRoot)
        }
    }

    return $Path
 }


# Relaunch the script if not admin
function Invoke-RequireAdmin
{
    Param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
    [System.Management.Automation.InvocationInfo]
    $MyInvocation)

    if (-not (Test-IsAdmin))
    {
        # Get the script path
		
        $scriptPath = $MyInvocation.MyCommand.Path
	
        $scriptPath = Get-UNCFromPath -Path $scriptPath
	
        # Need to quote the paths in case of spaces
        $scriptPath = '"' + $scriptPath + '"'

        # Build base arguments for powershell.exe
        [string[]]$argList = @('-NoLogo -NoProfile', '-ExecutionPolicy Bypass', '-File', $scriptPath)

        # Add 
        $argList += $MyInvocation.BoundParameters.GetEnumerator() | Foreach {"-$($_.Key)", "$($_.Value)"}
        $argList += $MyInvocation.UnboundArguments

        try
        {    
            $process = Start-Process PowerShell.exe -PassThru -Verb Runas -WorkingDirectory $pwd -ArgumentList $argList
            exit $process.ExitCode
        }
        catch {}

        # Generic failure code
        exit 1 
    }
}
Function Get-PendingReboot
{
<#
.SYNOPSIS
    Gets the pending reboot status on a local or remote computer.

.DESCRIPTION
    This function will query the registry on a local or remote computer and determine if the
    system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
    Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
    CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
    and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
	
    CBServicing = Component Based Servicing (Windows 2008+)
    WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
    CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
    PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
    PendFileRename = PendingFileRenameOperations (Windows 2003+)
    PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                     Virus leverage this key for def/dat removal, giving a false positive PendingReboot

.PARAMETER ComputerName
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER ErrorLog
    A single path to send error data to a log file.

.EXAMPLE
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
	
    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
    -------- ----------- ------------- ------------ -------------- -------------- -------------
    DC01           False         False                       False                        False
    DC02           False         False                       False                        False
    FS01           False         False                       False                        False

    This example will capture the contents of C:\ServerList.txt and query the pending reboot
    information from the systems contained in the file and display the output in a table. The
    null values are by design, since these systems do not have the SCCM 2012 client installed,
    nor was the PendingFileRenameOperations value populated.

.EXAMPLE
    PS C:\> Get-PendingReboot
	
    Computer           : WKS01
    CBServicing        : False
    WindowsUpdate      : True
    CCMClient          : False
    PendComputerRename : False
    PendFileRename     : False
    PendFileRenVal     : 
    RebootPending      : True
	
    This example will query the local machine for pending reboot information.
	
.EXAMPLE
    PS C:\> $Servers = Get-Content C:\Servers.txt
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
	
    This example will create a report that contains pending reboot information.

.LINK
    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
	
    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    SCCM 2012/CCM_ClientSDK:
    http://msdn.microsoft.com/en-us/library/jj902723.aspx

.NOTES
    Author:  Brian Wilhite
    Email:   bcwilhite (at) live.com
    Date:    29AUG2012
    PSVer:   2.0/3.0/4.0/5.0
    Updated: 27JUL2015
    UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
             Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
             Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
             Added CCMClient property - Used with SCCM 2012 Clients only
             Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
             Removed $Data variable from the PSObject - it is not needed
             Bug with the way CCMClientSDK returned null value if it was false
             Removed unneeded variables
             Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
             Removed .Net Registry connection, replaced with WMI StdRegProv
             Added ComputerPendingRename
#>

[CmdletBinding()]
param(
	[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[Alias("CN","Computer")]
	[String[]]$ComputerName="$env:COMPUTERNAME",
	[String]$ErrorLog
	)

Begin {  }## End Begin Script Block
Process {
  Foreach ($Computer in $ComputerName) {
	Try {
	    ## Setting pending values to false to cut down on the number of else statements
	    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                        
	    ## Setting CBSRebootPend to null since not all versions of Windows has this value
	    $CBSRebootPend = $null
						
	    ## Querying WMI for build version
	    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

	    ## Making registry connection to the local/remote computer
	    $HKLM = [UInt32] "0x80000002"
	    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
						
	    ## If Vista/2008 & Above query the CBS Reg Key
	    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
		    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
		    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
	    }
							
	    ## Query WUAU from the registry
	    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
	    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
	    ## Query PendingFileRenameOperations from the registry
	    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
	    $RegValuePFRO = $RegSubKeySM.sValue

	    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
	    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
	    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

	    ## Query ComputerName and ActiveComputerName from the registry
	    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
	    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

	    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
	        $CompPendRen = $true
	    }
						
	    ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
	    If ($RegValuePFRO) {
		    $PendFileRename = $true
	    }

	    ## Determine SCCM 2012 Client Reboot Pending Status
	    ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
	    $CCMClientSDK = $null
	    $CCMSplat = @{
	        NameSpace='ROOT\ccm\ClientSDK'
	        Class='CCM_ClientUtilities'
	        Name='DetermineIfRebootPending'
	        ComputerName=$Computer
	        ErrorAction='Stop'
	    }
	    ## Try CCMClientSDK
	    Try {
	        $CCMClientSDK = Invoke-WmiMethod @CCMSplat
	    } Catch [System.UnauthorizedAccessException] {
	        $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
	        If ($CcmStatus.Status -ne 'Running') {
	            Write-Warning "$Computer`: Error - CcmExec service is not running."
	            $CCMClientSDK = $null
	        }
	    } Catch {
	        $CCMClientSDK = $null
	    }

	    If ($CCMClientSDK) {
	        If ($CCMClientSDK.ReturnValue -ne 0) {
		        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
		    }
		    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
		        $SCCM = $true
		    }
	    }
            
	    Else {
	        $SCCM = $null
	    }

	    ## Creating Custom PSObject and Select-Object Splat
	    $SelectSplat = @{
	        Property=(
	            'Computer',
	            'CBServicing',
	            'WindowsUpdate',
	            'CCMClientSDK',
	            'PendComputerRename',
	            'PendFileRename',
	            'PendFileRenVal',
	            'RebootPending'
	        )}
	    New-Object -TypeName PSObject -Property @{
	        Computer=$WMI_OS.CSName
	        CBServicing=$CBSRebootPend
	        WindowsUpdate=$WUAURebootReq
	        CCMClientSDK=$SCCM
	        PendComputerRename=$CompPendRen
	        PendFileRename=$PendFileRename
	        PendFileRenVal=$RegValuePFRO
	        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
	    } | Select-Object @SelectSplat

	} Catch {
	    Write-Warning "$Computer`: $_"
	    ## If $ErrorLog, log the file to a user specified location/path
	    If ($ErrorLog) {
	        Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
	    }				
	}			
  }## End Foreach ($Computer in $ComputerName)			
}## End Process

End {  }## End End

}## End Function Get-PendingReboot
function Expand-ZIPFile($file, $destination)
{
	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($file)
	New-Item -ItemType Directory -Path $destination -Force -ErrorAction SilentlyContinue
	
	foreach ($item in $zip.items())
	{
		$shell.Namespace($destination).copyhere($item, 16 + 1024)
	}
}

function ConfigureFirewall
{
	Import-Module NetSecurity
	Set-NetFirewallProfile -Profile Domain -Enabled False
}
#David - can we fix it for single machine install - just to add the Domain users to the local RemoteDesktopUsers ?

function AddUsersToRemoteDesktopGroup
{
	$baseADGroupRDP = "Domain Users"
	Invoke-Command { param ([String]$RDPGroup) net localgroup "Remote Desktop Users" "$RDPGroup" /ADD } -computername "localhost" -ArgumentList "$baseADGroupRDP"
	
}

function CheckDomainRole
{
	# Get-ComputerRole.ps1
	$ComputerName = "localhost"
	
	$role = @{
		0 = "Stand alone workstation";
		1 = "Member workstation";
		2 = "Stand alone server";
		3 = "Member server";
		4 = "Back-up domain controller";
		5 = "Primary domain controller"
	}
	[int32]$myRole = (Get-WmiObject -Class win32_ComputerSystem -ComputerName $ComputerName).DomainRole
	Write-Host "$ComputerName is a $($role[$myRole]), role type $myrole"

	$response = $true;
	if ($myRole -eq 0 -or $myRole -eq 2)
	{
		Write-Warning "The machine should be in a domain!";
		$response = $false;
		
		$mail_error = "Computer " + (hostname) + "Is not part of a Domain, Please join to a Domain and try again"
		SendErrorMail  -Error "$mail_error"
        Exit 
	}
	return $response;
}

function CheckDNSConflict 
{
	$IP = (Get-NetIPAddress -AddressFamily IPv4)[0].IPAddress
	$Name = [System.Net.Dns]::GetHostByName((hostname)).HostName
	$IP_From_Name = [System.Net.Dns]::GetHostbyAddress((Get-NetIPAddress -AddressFamily IPv4)[0].IPAddress).HostName
	if ($IP_From_Name -ne $Name)
	{
    	# we have DNS problem
    	Write-Output "IP is          : $IP"
    	Write-Output "Name is        : $Name"
    	Write-Output "IP from Nams is: $IP_From_Name"
		$mail_error = "DNS problem detacted,<br>Computer IP is: "+ $IP + "<br>Computer DNS name is: "+ $Name + "<br> Computer name by IP is: "+ $IP_From_Name +"<br> Please refresh your DNS setting and try again"
		SendErrorMail  -Error "$mail_error"
    	exit
	}	
}
function CheckDNSWithPing
{
	$test1 = (Test-Connection -ComputerName (hostname) -Count 1 -erroraction Stop).IPV4Address.IPAddressToString
	$test2 = (Test-Connection -ComputerName ([System.Net.Dns]::GetHostByName((hostname)).HostName) -Count 1 -erroraction Stop).IPV4Address.IPAddressToString

	if ($test1 -ne $test2)
	{
		$DNS_error = "DNS problem detacted,<br>Ping by short name ("+ (hostname) + ") resolved to "+ $test1 + "<br>Ping by DNS name ("+ ([System.Net.Dns]::GetHostByName((hostname)).HostName) + ") resolved to "+ $test2 +"<br> Please refresh your DNS setting and try again"
    	Write-Output "$DNS_Error"
    	SendErrorMail  -Error "$DNS_error"
		exit
	}
}





function SendAdminMail ()
{
	New-Item -Path "C:\SendAdminMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$Subject = "Ericom Connect ESG Deployment on " + (hostname) + " is now Ready"
	
	$securePassword = ConvertTo-SecureString -String $SMTPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	
	Write-Verbose "Ericom Connect ESG has been succesfuly configured."

	$Message = '<h1>Congratulations! Your Ericom Connect ESG is now Ready!</h1><p>Dear ' + $ToName + ',<br><br>Thank you for deploying <a href="http://www.ericom.com/connect-enterprise.asp">Ericom Connect</a> on <b>'+ [System.Net.Dns]::GetHostByName((hostname)).HostName +'</b>.<br><br>Your deployment is now complete and you can start using the system with these links:<br><br>1. <a href="http://' + $externalFqdn + ':8033/EricomXml/AccessPortal/Start.html#/login">Ericom Connect Access Portal.</a><br>2. <a href="https://' + $externalFqdn + ':8022/Admin">Ericom Connect management console.</a><br><br>Below are your system information. Please make sure you save them for future use:<br><br><b>Server Name:</b><a href="http://' + $externalFqdn + ':8080/AccessNow/Start.html?username='+ $AdminUser+'&password='+ $AdminPassword +'&autostart=true">'+ [System.Net.Dns]::GetHostByName((hostname)).HostName + '</a><br><b>Username:</b> ' + $AdminUser + ' <br><b>Password:</b> ' + $AdminPassword + '<br><br><br>Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'
	if ($To -ne "nobody")
	{
		try
		{
			Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" -ErrorAction SilentlyContinue
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\sendmailmessageend.txt"
		}
	}

}

function SendErrorMail ()
{
	param (
		[string]$Error
	)
	
	$Subject = "Ericom Connect ESG Deployment have failed on " + (hostname)	
	$Message = '<h1>Ericom Connect ESG Deployment have failed!</h1><p>Dear Customer ,<br><br> Ericom Connect Deployment on ' + [System.Net.Dns]::GetHostByName((hostname)).HostName +' have failed with this error: <br><br><i>"' + $Error + '"</i> <br><br> Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'

	New-Item -Path "C:\SendProblemMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$securePassword = ConvertTo-SecureString -String $SMTPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	
	Write-Verbose "Ericom Connect Deployment have started."
		
	if ($To -ne "nobody")
	{
		try
		{
			Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" -ErrorAction SilentlyContinue
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\SendProblemMail.txt"
		}
	}	
}

function SendStartMail ()
{
	New-Item -Path "C:\SendStartMail" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	$Subject = "Ericom Connect ESG Deployment on " + (hostname) +" have started"
	
	$securePassword = ConvertTo-SecureString -String $SMTPassword -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
	$date = (Get-Date).ToString();
	$ToName = $To.Split("@")[0].Replace(".", " ");
	
	Write-Verbose "Ericom Connect Deployment have started."

	$Message = '<h1>You have successfully started your Ericom Connect Deployment!</h1><p>Dear ' + $ToName + ',<br><br>Thank you for using <a href="http://www.ericom.com/connect-enterprise.asp">Ericom Connect</a>.<br><br>Your Ericom Connect Deployment on <b>'+ [System.Net.Dns]::GetHostByName((hostname)).HostName +'</b> is now in process.<br><br>We will send you a confirmation e-mail once the deployment is complete and your system is ready.<br><br>Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'
	
	if ($To -ne "nobody")
	{
		try
		{
			Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $SMTPPort -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com", "DaaS@ericom.com" -ErrorAction SilentlyContinue
		}
		catch
		{
			$_.Exception.Message | Out-File "C:\sendmailmessageend.txt"
		}
	}
}
function CheckPrerequisite
{
	# make sure that this machine is part of a domain
	CheckDomainRole

	# make sure that this machine name can be found in DNS
	CheckDNSConflict
	
	# check DNS using ping
	CheckDNSWithPing
}

function Install-Apps
{
	# list of possilbe apps (4000) can be found here - https://chocolatey.org/packages
	New-Item -Path "C:\Install-Apps" -ItemType Directory -Force -ErrorAction SilentlyContinue
	Write-Output "Apps installation has been started."
	
	iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
	Write-Output "Apps installation has been ended."
}
function Install-WindowsFeatures
{
	# list of Windows Features can be found here - https://blogs.technet.microsoft.com/canitpro/2013/04/23/windows-server-2012-roles-features/
	New-Item -Path "C:\Install-WindowsFeatures" -ItemType Directory -Force -ErrorAction SilentlyContinue
	
	Install-WindowsFeature RSAT-AD-PowerShell
	Install-WindowsFeature Net-Framework-45-Core
		
	$needReboot = Get-PendingReboot
	if ($false) # ($needReboot.RebootPending -eq $true)
	{
        $UserSelection = Show-MessageBox -Msg "In Order to continue a restart is requierd, Press OK to Restart or Canel to abort" -OC -T "Ericom Connect Deploy" -Q 
  
         
        if ($UserSelection -eq "OK" )  
        { 
		$fileExec = $MyInvocation.MyCommand.Path
		$argumentList =""
		if ($fileExec.length -gt 0)
		{
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name "ScriptContinueOnReboot" -Force -PropertyType String -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File "' + $fileExec + '"' + " " + $argumentList) |Out-Null
		}
		Restart-Computer -Force
	} 
        else  
        {  
            exit
        }  
		
	} 
	
}

function Windows-Configuration
{
	#Configure firwall 
	ConfigureFirewall
	
	#change IE Security
	Disable-IEESC
	
	# Allow Multiple RDP Sessions Per User
	AllowMultipleSessionsPerUser
	
	# Add Domain Users To local Remote Desktop Group
	AddUsersToRemoteDesktopGroup
}

function PostInstall
{
    # Install varius applications on the machine
	Install-Apps
}












# Main Code 

# Relaunch if we are not running as admin

Invoke-RequireAdmin $script:MyInvocation

# Prerequisite check 
CheckPrerequisite 

# Install the needed Windows Features 
Install-WindowsFeatures

# Windows Configuration
Windows-Configuration

# Download Ericom Offical Installers from the Ericom Web site or network path 
Download-ESG

# Install Ericom Secure Gateway in a single machine mode including SQL express   
Install-ESG

# We can stop here with a system ready and connected installed and not cofigured 
if ($PrepareSystem -eq $true)
{
	# Configure Ericom Connect Grid
	Config-JoinGrid 
	
	# Run PostInstall Creating users,apps,desktops and publish them
	PostInstall
}
