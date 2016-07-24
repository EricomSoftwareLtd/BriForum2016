configuration CreateADPDC 
{ 
   param 
   ( 
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds, 
        
        [String]$emailAddress = "nobody",

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    ) 
    
    Import-DscResource -ModuleName xActiveDirectory, xDisk, xNetworking, xPendingReboot, cDisk
    $adminUsername = $Admincreds.UserName
    [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

    Node localhost
    {
        LocalConfigurationManager            
        {            
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true            
        } 
        
        Script SendStartEmail
        {
            TestScript = {
                Test-Path "C:\SendStartEmailExecuted\"
            }
            SetScript = {
                New-Item -Path "C:\SendStartEmailExecuted" -ItemType Directory -Force -ErrorAction SilentlyContinue
                
                # send initial mail - might need a better place for it
                $To = "nobody"
                $Subject = "Ericom Connect Deployment on Azure have started"
                $Message = ""
                $Keyword = ""
                $From = "daas@ericom.com"
                $date = (Get-Date).ToString();
                $SMTPServer = "ericom-com.mail.protection.outlook.com"
                $Port = 25
                if ($Using:emailAddress -ne "") {
                    $To = $Using:emailAddress
                }
          
                $securePassword = ConvertTo-SecureString -String "1qaz@Wsx#" -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
                
                Write-Verbose "Ericom Connect Deployment have started."
                $Keyword = "Ericom Connect Deployment have started."
                $ToName = $To.Split("@")[0].Replace(".", " ");
                $Message = '<h1>You have successfully started your Ericom Connect Deployment on Azure!</h1><p>Dear ' + $ToName + ',<br><br>Thank you for using <a href="http://www.ericom.com/connect-enterprise.asp">Ericom Connect</a> via Microsoft Azure.<br><br>Your Ericom Connect Deployment is now in process.<br><br>We will send you a confirmation e-mail once the deployment is complete and your system is ready.<br><br>Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'
                if ($To -ne "nobody") {
                    try {
                        Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $Port -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com","DaaS@ericom.com","David.Oprea@ericom.com" -ErrorAction SilentlyContinue
                    } catch {
                        $_.Exception.Message | Out-File "C:\sendmailmessagestart.txt"
                    }
                }
                # end sending the mail
            }
            GetScript = {@{Result = "SendStartEmail"}}
        } 

        WindowsFeature DNS 
        { 
            Ensure = "Present" 
            Name = "DNS"
        }

        xDnsServerAddress DnsServerAddress 
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            DependsOn = "[WindowsFeature]DNS"
        }

        xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }

        cDiskNoRestart ADDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
        }

        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services"
            IncludeAllSubFeature = $True
        }  

        xADDomain FirstDS 
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
            DependsOn = "[WindowsFeature]ADDSInstall","[xDnsServerAddress]DnsServerAddress","[cDiskNoRestart]ADDataDisk"
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $DomainName
            DomainUserCredential = $DomainCreds
            RetryCount = $RetryCount
            RetryIntervalSec = $RetryIntervalSec
            DependsOn = "[xADDomain]FirstDS"
        } 

        xPendingReboot Reboot1
        { 
            Name = "RebootServer"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

	   Script CreateADUsers
        {
            TestScript = { Test-Path "C:\aduserscreated" }
            SetScript = {
                $domainSuffix = "@" + $Using:DomainName;
                $templateUser = "$Using:adminUsername"
                $user = "demouser"
                $pass = "P@55w0rd"
                
                New-ADUser -name "$user" -Instance (Get-ADUser $templateUser) -AccountPassword (ConvertTo-SecureString "$pass" -AsPlainText -Force) -ChangePasswordAtLogon $False -CannotChangePassword $True -Enabled $True -GivenName "$user" -SamAccountName "$user" -Surname ="$user" -UserPrincipalName ("$user" + "$domainSuffix")
                New-Item -Path "C:\aduserscreated" -ItemType Directory -Force 
                
                Add-ADGroupMember -Identity (Get-ADGroup "Remote Desktop Users") -Members "$user"
            }
            GetScript = {@{Result = "CreateADUsers"}}
        }

        Script FixUPNSuffix
        {
            TestScript = {
                Test-Path "C:\adupnsuffix"
            }
            SetScript ={
                # Fix UPN suffix                
                $domainSuffix = "@" + $Using:DomainName;
                Get-ADUser -Filter * | Where { $_.Enabled -eq $true } | foreach { Set-ADUser $_ -UserPrincipalName "$($_.samaccountname)$domainSuffix" }
                New-Item -Path "C:\adupnsuffix" -ItemType Directory 
                
            }
            GetScript = {@{Result = "FixUPNSuffix"}}      
        }
   }
} 