configuration DomainJoin 
{ 
   param 
    ( 
        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [PSCredential]$adminCreds
    )
    
    Import-DscResource -ModuleName xActiveDirectory, xComputerManagement

    $domainCreds = New-Object System.Management.Automation.PSCredential ("$domainName\$($adminCreds.UserName)", $adminCreds.Password)
   
    $_Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString ($adminCreds.Password | ConvertFrom-SecureString)) ))
    
    Write-Verbose ($adminCreds.UserName + " " + $_Password)
  
    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        WindowsFeature ADPowershell
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        } 

        xComputer DomainJoin
        {
            Name = $env:COMPUTERNAME
            DomainName = $domainName
            Credential = $domainCreds
            DependsOn = "[WindowsFeature]ADPowershell" 
        }
   }
}

configuration EnableRemoteAdministration
{
	param
	(
		[Parameter(Mandatory)]
		[String]$broker
	)

	Node localhost 
	{
		LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }
		
		Script SetRDA
		{
			TestScript = {
                Test-Path "C:\RDAEnabled\"
            }
            SetScript ={
				New-Item -Path "C:\RDAEnabled" -ItemType Directory -Force -ErrorAction SilentlyContinue
                Enable-PSRemoting -Force
				$broker = "$Using:broker"
				Set-Item wsman:\localhost\Client\TrustedHosts -value $broker
            }
            GetScript = {@{Result = "SetRDA"}}
		}
	}
}

configuration EnableRemoteDesktopForDomainUsers
{
	Node localhost 
	{
		LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }
		
		Script SetRDS
		{
			TestScript = {
                Test-Path "C:\RDSEnabled\"
            }
            SetScript ={
				New-Item -Path "C:\RDSEnabled" -ItemType Directory -Force -ErrorAction SilentlyContinue
				$baseADGroupRDP = "Domain Users"
                Invoke-Command { param([String]$RDPGroup) net localgroup "Remote Desktop Users" "$RDPGroup" /ADD } -computername "localhost" -ArgumentList "$baseADGroupRDP"
            }
            GetScript = {@{Result = "SetRDS"}}
		}
	}
}

configuration EnableRunningScripts
{
	Node localhost 
	{
		LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }
		
		Script SetExecutionPolicy
		{
			TestScript = {
                Test-Path "C:\ExecutionPolicy\"
            }
            SetScript ={
				New-Item -Path "C:\ExecutionPolicy" -ItemType Directory -Force -ErrorAction SilentlyContinue
				try {
					Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false -ErrorAction SilentlyContinue
				} catch { }
            }
            GetScript = {@{Result = "SetExecutionPolicy"}}
		}
	}
}

configuration GatewaySetup
{
   param 
    ( 
        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [PSCredential]$adminCreds,
                
        [String]$externalFqdn,
        
        [String]$emailAddress = "nobody",
		
		[Parameter(Mandatory)]
        [String]$gridName,
		
		[Parameter(Mandatory)]
        [String]$LUS,
		
		[Parameter(Mandatory)]
        [String]$tenant,
        
        [Parameter(Mandatory)]
        [String]$softwareBaseLocation
        
    ) 

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xActiveDirectory, xComputerManagement
    
    $_adminUser = $adminCreds.UserName
    $_adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString ($adminCreds.Password | ConvertFrom-SecureString)) ))
   


    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        DomainJoin DomainJoin
        {
            domainName = $domainName 
            adminCreds = $adminCreds 
        }
        
        Script DownloadGridMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectDataGrid_x64_WT.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectDataGrid_x64_WT.msi")
                $dest = "C:\EricomConnectDataGrid_x64_WT.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadGridMSI"}}
      
        }
		
        Package InstallGridMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectDataGrid_x64_WT.msi"
            Name = "Ericom Connect Data Grid"
            ProductId = "08CD0EA8-6E2D-43B5-BE12-9F0AAF6034EA"
            Arguments = ""
            LogPath = "C:\log-ecdg.txt"
            DependsOn = "[Script]DownloadGridMSI"
        }

	    Script DownloadSecureGatewayMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectSecureGateway.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectSecureGateway.msi")
                $dest = "C:\EricomConnectSecureGateway.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadSecureGatewayMSI"}}
        }
		
        Package InstallSecureGatewayMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectSecureGateway.msi"
            Name = "Ericom Connect Secure Gateway"
            ProductId = "50EE13E5-E7AF-49DE-BF38-6D86411235B5"
            Arguments = ""
            LogPath = "C:\log-ecsg.txt"
            DependsOn = "[Script]DownloadSecureGatewayMSI"
        }
                
        Package vcRedist 
        { 

            Path = ($softwareBaseLocation+"vcredist_x64.exe" )
            ProductId = "{DA5E371C-6333-3D8A-93A4-6FD5B20BCC6E}" 
            Name = "Microsoft Visual C++ 2010 x64 Redistributable - 10.0.30319" 
            Arguments = "/install /passive /norestart"
 
        } 

        Script DisableFirewallDomainProfile
        {
            TestScript = {
                return ((Get-NetFirewallProfile -Profile Domain).Enabled -eq $false)
            }
            SetScript = {
                Set-NetFirewallProfile -Profile Domain -Enabled False
            }
            GetScript = {@{Result = "DisableFirewallDomainProfile"}}
        }
        
        Script JoinGridESG
        {
            TestScript = {
                $isESGRunning = $false;
                $allServices = Get-Service | Where { $_.DisplayName.StartsWith("Ericom")}
                foreach($service in $seallServicesrvices)
                {
                    if ($service.Name -contains "EricomConnectSecureGateway") {
                        if ($service.Status -eq "Running") {
                            Write-Verbose "ESG service is running"
                            $isESGRunning = $true;
                        } elseif ($service.Status -eq "Stopped") {
                            Write-Verbose "ESG service is stopped"
                            $isESGRunning = $false;
                        } else {
                            $statusESG = $service.Status
                            Write-Verbose "ESG status: $statusESG"
                        }
                    }
                }
                return ($isESGRunning -eq $true);
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
                # Call Configuration Tool
                Write-Verbose "Configuration step"
                $workingDirectory = "$env:ProgramFiles\Ericom Software\Ericom Connect Configuration Tool"
                $configFile = "EricomConnectConfigurationTool.exe"
                $connectCli = "ConnectCli.exe"                  

                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                $_gridName = "$Using:gridName"
                $_gridServicePassword = "$Using:_adminPassword"
                $_lookUpHosts = "$Using:LUS"

                $configPath = Join-Path $workingDirectory -ChildPath $configFile
                $cliPath = Join-Path $workingDirectory -ChildPath $connectCli
                
                $arguments = " ConnectToExistingGrid /AdminUser `"$_adminUser`" /AdminPassword `"$_adminPass`" /disconnect /GridName `"$_gridName`" /GridServicePassword `"$_gridServicePassword`"  /LookUpHosts `"$_lookUpHosts`""              

                $baseFileName = [System.IO.Path]::GetFileName($configPath);
                $folder = Split-Path $configPath;
                cd $folder;
                Write-Verbose "$configPath $arguments"
                $exitCode = (Start-Process -Filepath $configPath -ArgumentList "$arguments" -Wait -Passthru).ExitCode
                if ($exitCode -eq 0) {
                    Write-Verbose "Ericom Connect Secure Gateway has been succesfuly configured."
                } else {
                    Write-Verbose ("Ericom Connect Secure Gateway could not be configured. Exit Code: " + $exitCode)
                }
                
                # publish admin page via ESG
                $argumentsCli = "EsgConfig /adminUser `"$_adminUser`" /adminPassword `"$_adminPass`" common ExternalWebServer`$UrlServicePointsFilter=`"<UrlServicePointsFilter> <UrlFilter> <UrlPathRegExp>^/Admin</UrlPathRegExp> <UrlServicePoints>https://`"$_lookUpHosts`":8022/</UrlServicePoints></UrlFilter><UrlFilter> <UrlPathRegExp>^/EricomAutomation</UrlPathRegExp> <UrlServicePoints>http://`"$_lookUpHosts`":2244/</UrlServicePoints></UrlFilter> <UrlFilter> <UrlPathRegExp>^/rdweb</UrlPathRegExp> <UrlServicePoints>https://`"$_lookUpHosts`"/</UrlServicePoints></UrlFilter> </UrlServicePointsFilter>`"";
              
                $exitCodeCli = (Start-Process -Filepath $cliPath -ArgumentList "$argumentsCli" -Wait -Passthru).ExitCode;
                if ($exitCodeCli -eq 0) {
                    Write-Verbose "ESG: Admin page has been succesfuly published."
                } else {
                    Write-Verbose "$cliPath $argumentsCli"
                    Write-Verbose ("ESG: Admin page could not be published.. Exit Code: " + $exitCode)
                }                 
            }
            GetScript = {@{Result = "JoinGridESG"}}      
        }
        
        Script SendEndEmail
        {
            TestScript = {
                Test-Path "C:\SendEndEmailExecuted\"
            }
            SetScript = {
                New-Item -Path "C:\SendEndEmailExecuted" -ItemType Directory -Force -ErrorAction SilentlyContinue
                $domainSuffix = "@" + $Using:domainName;
                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                # send system is ready mail - might need a better place for it
                $To = "nobody"
                $Subject = "Ericom Connect Deployment on Azure is now Ready"
                $Message = ""
                $Keyword = ""
                $From = "daas@ericom.com"
                $date=(Get-Date).TOString();
                $SMTPServer = "ericom-com.mail.protection.outlook.com"
                $Port = 25
                $_externalFqdn = $Using:externalFqdn
                
                if ($Using:emailAddress -ne "") {
                    $To = $Using:emailAddress
                }
                    
                $securePassword = ConvertTo-SecureString -String "1qaz@Wsx#" -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential ("daas@ericom.com", $securePassword)
                $date = (Get-Date).ToString();	
                $ToName = $To.Split("@")[0].Replace(".", " ");

                Write-Verbose "Ericom Connect Grid Server has been succesfuly configured."
                $Keyword = "CB: Ericom Connect Grid Server has been succesfuly configured."
                $Message = '<h1>Congratulations! Your Ericom DaaS Environment on Microsoft Azure is now Ready!</h1><p>Dear ' + $ToName + ',<br><br>Thank you for deploying <a href="http://www.ericom.com/connect-enterprise.asp">Ericom Connect</a> via Microsoft Azure.<br><br>Your deployment is now complete and you can start using the system.<br><br>To launch Ericom DaaS Client please click <a href="https://' + $_externalFqdn + '/EricomAutomation/DaaS/index.html#/register">here. </a><br><br>To log-in to Ericom Connect management console please click <a href="https://' + $_externalFqdn + '/Admin">here. </a><br><br><Below are your Admin credentials. Please make sure you save them for future use:<br><br>Username: ' + $_adminUser + ' <br>Password: '+ $_adminPass  + '<br><br><br>Regards,<br><a href="http://www.ericom.com">Ericom</a> Automation Team'
                if ($To -ne "nobody") {
                    try {
                        Send-MailMessage -Body "$Message" -BodyAsHtml -Subject "$Subject" -SmtpServer $SmtpServer -Port $Port -Credential $credential -From $credential.UserName -To $To -bcc "erez.pasternak@ericom.com","DaaS@ericom.com","David.Oprea@ericom.com" -ErrorAction SilentlyContinue
                    } catch {
                        $_.Exception.Message | Out-File "C:\sendmailmessageend.txt"
                    }
                }                               
                #done sending mail
            }
            GetScript = {@{Result = "SendEndEmail"}}
        } 
        Script StartBootStrapOnBroker
        {
   
            SetScript = {

                    New-Item -Path "C:\SendBootStrapCommand" -ItemType Directory -Force -ErrorAction SilentlyContinue
                    $data = @{command='Bootstrap'}
                    $json = $data | ConvertTo-Json
                    try {
                        $_lookUpHosts = "$Using:LUS"
                        $uri = 'http://'+$_lookUpHosts+':2244/EricomAutomation/command/Generic'
                        $Request = [System.UriBuilder]$uri
                        $response = Invoke-RestMethod -Uri $Request.Uri -TimeoutSec 400 -Method Post -Body $json -ContentType 'application/json' 
                    }
                    catch {
                        $response | Out-file "C:\Bootstrap.txt"
                    }
                    Finally {
                        $response | Out-file "C:\Bootstrap.txt"
                    }
              }
    
        TestScript = {
            Test-Path "C:\SendBootStrapCommand\"
        }
    
        GetScript = {@{Result = "StartBootStrapOnBroker"}}

        }
        
    }
}


configuration DesktopHost
{
   param 
    ( 
        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [PSCredential]$adminCreds,
		
	    [Parameter(Mandatory)]
        [String]$gridName,
		
	    [Parameter(Mandatory)]
        [String]$LUS,
		
	    [Parameter(Mandatory)]
        [String]$tenant,
        
        [Parameter(Mandatory)]
        [String]$softwareBaseLocation
        
    ) 

    $_adminUser = $adminCreds.UserName
    $domainCreds = New-Object System.Management.Automation.PSCredential ("$domainName\$_adminUser", $adminCreds.Password)
    $_adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString ($adminCreds.Password | ConvertFrom-SecureString)) ))

    $accessPadShortCut = "-accesspad /server=" + $LUS + ":8011"

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        DomainJoin DomainJoin
        {
            domainName = $domainName 
            adminCreds = $adminCreds 
        }

		EnableRemoteAdministration EnableRemoteAdministration
		{
			broker = $LUS
		}
		
		EnableRemoteDesktopForDomainUsers EnableRemoteDesktopForDomainUsers
		{
		}

        WindowsFeature RDS-RD-Server
        {
            Ensure = "Present"
            Name = "RDS-RD-Server"
        }
	    
       # WindowsFeature Desktop-Experience
       # {
       #     Ensure = "Present"
       #     Name = "Desktop-Experience"
       # IncludeAllSubFeature  = $True
       # }
		
        # Downloading and installing Ericom connect components 
	    Script DownloadGridMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectDataGrid_x64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectDataGrid_x64.msi")
                $dest = "C:\EricomConnectDataGrid_x64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadGridMSI"}}
      
        }
		
        Package InstallGridMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectDataGrid_x64.msi"
            Name = "Ericom Connect Data Grid"
            ProductId = "08CD0EA8-6E2D-43B5-BE12-9F0AAF6034EA"
            Arguments = ""
            LogPath = "C:\log-ecdg.txt"
            DependsOn = "[Script]DownloadGridMSI"
        }
        
	    Script DownloadRemoteAgentMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectRemoteAgentClient_x64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectRemoteAgentClient_x64.msi")
                $dest = "C:\EricomConnectRemoteAgentClient_x64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadRemoteAgentMSI"}}
      
        }
		
        Package InstallRemoteAgentMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectRemoteAgentClient_x64.msi"
            Name = "Ericom Connect Remote Agent Client"
            ProductId = "CFEC51AA-449F-4BCD-AB5C-65E337C45475"
            Arguments = ""
            LogPath = "C:\log-ecrac.txt"
            DependsOn = "[Script]DownloadRemoteAgentMSI"
        }
        # End of Downloading and installing Ericom connect components
        
        # AccessServer 
	    Script DownloadAccessServerMSI
        {
            TestScript = {
                Test-Path "c:\EricomAccessServer64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomAccessServer64.msi")
                $dest = "C:\EricomAccessServer64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadAccessServerMSI"}}
        }
		
        Package InstallAccessServerMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomAccessServer64.msi"
            Name = "Ericom Access Server"
            ProductId = "A9E98E7C-0358-4D86-9016-08399CEF68E5"
            Arguments = ""
            LogPath = "C:\log-eas.txt"
            DependsOn = "[Script]DownloadAccessServerMSI"
        }
        #end of AccessServer 
        
	    Package vcRedist 
        { 
            Path = ($softwareBaseLocation + "vcredist_x64.exe") 
            ProductId = "{DA5E371C-6333-3D8A-93A4-6FD5B20BCC6E}" 
            Name = "Microsoft Visual C++ 2010 x64 Redistributable - 10.0.30319" 
            Arguments = "/install /passive /norestart" 
        }
        
        Script DisableFirewallDomainProfile
        {
            TestScript = {
                return ((Get-NetFirewallProfile -Profile Domain).Enabled -eq $false)
            }
            SetScript = {
                Set-NetFirewallProfile -Profile Domain -Enabled False
            }
            GetScript = {@{Result = "DisableFirewallDomainProfile"}}
        }

        Script JoinGridRemoteAgent
        {
            TestScript = {
                $isRARunning = $false;
                $allServices = Get-Service | Where { $_.DisplayName.StartsWith("Ericom")}
                foreach($service in $seallServicesrvices)
                {
                    if ($service.Name -contains "EricomConnectRemoteAgentService") {
                        if ($service.Status -eq "Running") {
                            Write-Verbose "ECRAS service is running"
                            $isRARunning = $true;
                        } elseif ($service.Status -eq "Stopped") {
                            Write-Verbose "ECRAS service is stopped"
                            $isRARunning = $false;
                        } else {
                            $statusECRAS = $service.Status
                            Write-Verbose "ECRAS status: $statusECRAS"
                        }
                    }
                }
                return ($isRARunning -eq $true);
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
                # Call Configuration Tool
                Write-Verbose "Configuration step"
                $workingDirectory = "$env:ProgramFiles\Ericom Software\Ericom Connect Remote Agent Client"
                $configFile = "RemoteAgentConfigTool_4_5.exe"                

                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                $_gridName = "$Using:gridName"
                $_lookUpHosts = "$Using:LUS"


                $configPath = Join-Path $workingDirectory -ChildPath $configFile
                
                $arguments = " connect /gridName `"$_gridName`" /myIP `"$env:COMPUTERNAME`" /lookupServiceHosts `"$_lookUpHosts`""                

                $baseFileName = [System.IO.Path]::GetFileName($configPath);
                $folder = Split-Path $configPath;
                cd $folder;
                
                $exitCode = (Start-Process -Filepath $configPath -ArgumentList "$arguments" -Wait -Passthru).ExitCode
                if ($exitCode -eq 0) {
                    Write-Verbose "Ericom Connect Remote Agent has been succesfuly configured."
                } else {
                    Write-Verbose ("Ericom Connect Remote Agent could not be configured. Exit Code: " + $exitCode)
                }                
            }
            GetScript = {@{Result = "JoinGridRemoteAgent"}}      
        }
        
        # AccessPad 
	    Script DownloadAccessPadMSI
        {
            TestScript = {
                Test-Path "C:\EricomAccessPadClient64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomAccessPadClient64.msi") 
                $dest = "C:\EricomAccessPadClient64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadAccessPadMSI"}}
      
        }
		
        Package InstallAccessAccessPadMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomAccessPadClient64.msi"
            Name = "Ericom AccessPad Client"
            ProductId = "F40C44B7-F2D4-4365-BFD6-B21E707F3ACE"
            Arguments = "ESSO=1 SHORTCUT_PARAMS=`"$accessPadShortCut`""
            LogPath = "C:\log-eap.txt"
            DependsOn = "[Script]DownloadAccessPadMSI"
        }
               
        Registry Reg_AccessPad
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            ValueType   = "String"
            ValueName   = "AccessPad"
            ValueData   = "`"C:\Program Files\Ericom Software\Ericom AccessPad Client\Blaze.exe`" -accesspad /server=`"$LUS`:8011`""
            Force       = $true
            Ensure      = "Present"
            DependsOn   = "[Script]DownloadAccessPadMSI"
        }
        
        # end of AccessPad 
        # BgInfo
        Script DownloadBGinfo
        {
            TestScript = {
                Test-Path "C:\BGInfo.zip"
            }
            SetScript ={
               
                $source = ("https://raw.githubusercontent.com/ErezPasternak/azure-quickstart-templates/EricomConnect/EricomConnectDaaS752/BGinfo/BGInfo.zip")
                $dest = "C:\BGInfo.zip"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadBGinfo"}}
        }

        Archive UnZip_BGInfo
        {
            Path        = "C:\BGInfo.zip"
            Destination = "C:\BgInfo"
            Force       = $True
            Ensure      = "Present"
            DependsOn   = "[Script]DownloadBGinfo"
        }

        Script DownloadBGinfoConfig
        {
            TestScript = {
                Test-Path "C:\BgInfo\bginfo_config.bgi"
            }
            SetScript ={
               
                $source = ("https://raw.githubusercontent.com/ErezPasternak/azure-quickstart-templates/EricomConnect/EricomConnectDaaS752/BGinfo/bginfo_config.bgi")
                $dest = "C:\BgInfo\bginfo_config.bgi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadBGinfoConfig"}}
        }
    
        Script DownloadWallpaper
        {
            TestScript = {
                Test-Path "C:\BgInfo\wall.jpg"
            }
            SetScript ={
               
                $source = ("https://raw.githubusercontent.com/ErezPasternak/azure-quickstart-templates/EricomConnect/EricomConnectDaaS752/BGinfo/wall.jpg")
                $dest = "C:\BgInfo\wall.jpg"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadWallpaper"}}
        }
   
        Registry Reg_BGInfo
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            ValueType   = "String"
            ValueName   = "bginfo"
            ValueData   = "C:\BgInfo\bginfo.exe C:\BgInfo\bginfo_config.bgi /silent /accepteula /timer:0"
            Force       = $true
            Ensure      = "Present"
            DependsOn   = @("[Archive]UnZip_BGInfo","[Script]DownloadBGinfo")
        }
        # End of Bg info
    }

}

configuration ApplicationHost
{
   param 
    ( 
        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [PSCredential]$adminCreds,
		
		[Parameter(Mandatory)]
        [String]$gridName,
				
	    [Parameter(Mandatory)]
        [String]$LUS,
		
	    [Parameter(Mandatory)]
        [String]$tenant,
        
        [Parameter(Mandatory)]
        [String]$softwareBaseLocation
    ) 
    Import-DscResource -ModuleName xActiveDirectory, xComputerManagement, cChoco
    
    $_adminUser = $adminCreds.UserName
    $domainCreds = New-Object System.Management.Automation.PSCredential ("$domainName\$_adminUser", $adminCreds.Password)
    $_adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString ($adminCreds.Password | ConvertFrom-SecureString)) ))

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        DomainJoin DomainJoin
        {
            domainName = $domainName 
            adminCreds = $adminCreds 
        }

		EnableRemoteAdministration EnableRemoteAdministration
		{
			broker = $LUS
		}
		
		EnableRemoteDesktopForDomainUsers EnableRemoteDesktopForDomainUsers
		{
		}

        WindowsFeature RDS-RD-Server
        {
            Ensure = "Present"
            Name = "RDS-RD-Server"
        }
      
        Script DownloadGridMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectDataGrid_x64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectDataGrid_x64.msi")
                $dest = "C:\EricomConnectDataGrid_x64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadGridMSI"}}
        }
		
        Package InstallGridMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectDataGrid_x64.msi"
            Name = "Ericom Connect Data Grid"
            ProductId = "08CD0EA8-6E2D-43B5-BE12-9F0AAF6034EA"
            Arguments = ""
            LogPath = "C:\log-ecdg.txt"
            DependsOn = "[Script]DownloadGridMSI"
        }
        
	    Script DownloadRemoteAgentMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectRemoteAgentClient_x64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectRemoteAgentClient_x64.msi")
                $dest = "C:\EricomConnectRemoteAgentClient_x64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadRemoteAgentMSI"}}
      
         }
		
        Package InstallRemoteAgentMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectRemoteAgentClient_x64.msi"
            Name = "Ericom Connect Remote Agent Client"
            ProductId = "CFEC51AA-449F-4BCD-AB5C-65E337C45475"
            Arguments = ""
            LogPath = "C:\log-ecrac.txt"
            DependsOn = "[Script]DownloadRemoteAgentMSI"
        }

	    Script DownloadAccessServerMSI
        {
            TestScript = {
                Test-Path "c:\EricomAccessServer64.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomAccessServer64.msi")
                $dest = "C:\EricomAccessServer64.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadAccessServerMSI"}} 
        }
		
        Package InstallAccessServerMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomAccessServer64.msi"
            Name = "Ericom Access Server"
            ProductId = "A9E98E7C-0358-4D86-9016-08399CEF68E5"
            Arguments = ""
            LogPath = "C:\log-eas.txt"
            DependsOn = "[Script]DownloadAccessServerMSI"
        }

	    Package vcRedist 
        { 
            Path = ($softwareBaseLocation + "vcredist_x64.exe") 
            ProductId = "{DA5E371C-6333-3D8A-93A4-6FD5B20BCC6E}" 
            Name = "Microsoft Visual C++ 2010 x64 Redistributable - 10.0.30319" 
            Arguments = "/install /passive /norestart" 
        }
        
        Script DisableFirewallDomainProfile
        {
            TestScript = {
                return ((Get-NetFirewallProfile -Profile Domain).Enabled -eq $false)
            }
            SetScript = {
                Set-NetFirewallProfile -Profile Domain -Enabled False
            }
            GetScript = {@{Result = "DisableFirewallDomainProfile"}}
        }

        Script JoinGridRemoteAgent
        {
            TestScript = {
                $isRARunning = $false;
                $allServices = Get-Service | Where { $_.DisplayName.StartsWith("Ericom")}
                foreach($service in $seallServicesrvices)
                {
                    if ($service.Name -contains "EricomConnectRemoteAgentService") {
                        if ($service.Status -eq "Running") {
                            Write-Verbose "ECRAS service is running"
                            $isRARunning = $true;
                        } elseif ($service.Status -eq "Stopped") {
                            Write-Verbose "ECRAS service is stopped"
                            $isRARunning = $false;
                        } else {
                            $statusECRAS = $service.Status
                            Write-Verbose "ECRAS status: $statusECRAS"
                        }
                    }
                }
                return ($isRARunning -eq $true);
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
                # Call Configuration Tool
                Write-Verbose "Configuration step"
                $workingDirectory = "$env:ProgramFiles\Ericom Software\Ericom Connect Remote Agent Client"
                $configFile = "RemoteAgentConfigTool_4_5.exe"                

                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                $_gridName = "$Using:gridName"
                $_lookUpHosts = "$Using:LUS"


                $configPath = Join-Path $workingDirectory -ChildPath $configFile
                
                $arguments = " connect /gridName `"$_gridName`" /myIP `"$env:COMPUTERNAME`" /lookupServiceHosts `"$_lookUpHosts`""                

                $baseFileName = [System.IO.Path]::GetFileName($configPath);
                $folder = Split-Path $configPath;
                cd $folder;
                
                $exitCode = (Start-Process -Filepath $configPath -ArgumentList "$arguments" -Wait -Passthru).ExitCode
                if ($exitCode -eq 0) {
                    Write-Verbose "Ericom Connect Remote Agent has been succesfuly configured."
                } else {
                    Write-Verbose ("Ericom Connect Remote Agent could not be configured. Exit Code: " + $exitCode)
                }                
            }
            GetScript = {@{Result = "JoinGridRemoteAgent"}}      
        }
        
        Script StartBootStrapOnBroker
        {
   
            SetScript = {

                    New-Item -Path "C:\SendBootStrapCommandRDSH" -ItemType Directory -Force -ErrorAction SilentlyContinue
                    $data = @{command='Bootstrap'}
                    $json = $data | ConvertTo-Json
                    try {
                        $_lookUpHosts = "$Using:LUS"
                        $uri = 'http://'+$_lookUpHosts+':2244/EricomAutomation/command/Generic'
                        $Request = [System.UriBuilder]$uri
                        $response = Invoke-RestMethod -Uri $Request.Uri -TimeoutSec 400 -Method Post -Body $json -ContentType 'application/json' 
                    }
                    catch {
                        $response | Out-file "C:\Bootstraprdsh.txt"
                    }
                    Finally {
                        $response | Out-file "C:\Bootstraprdsh.txt"
                    }
              }
    
        TestScript = {
            Test-Path "C:\SendBootStrapCommandRDSH\"
        }
    
        GetScript = {@{Result = "StartBootStrapOnBroker"}}
      }
    }
}

configuration EricomConnectServerSetup
{
   param 
    ( 
        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [PSCredential]$adminCreds,

        # Gateway external FQDN
        [String]$externalFqdn,
        
        # Grid Name
        [String]$gridName,

        # sql server 
        [String]$sqlserver,
        
        # sql database
        [String]$sqldatabase,
        
         # sql credentials 
        [Parameter(Mandatory)]
        [PSCredential]$sqlCreds,
        
        [Parameter(Mandatory)]
		[String]$customScriptLocation,
        
        [Parameter(Mandatory)]
        [String]$softwareBaseLocation,
        
        [Parameter(Mandatory)]
        [String]$baseADGroupRDP,

        [Parameter(Mandatory)]
        [String]$remoteHostPattern

    ) 

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xActiveDirectory, xComputerManagement, xRemoteDesktopSessionHost, xSqlPs

   
    $localhost = [System.Net.Dns]::GetHostByName((hostname)).HostName

    $_adminUser = $adminCreds.UserName
    $domainCreds = New-Object System.Management.Automation.PSCredential ("$domainName\$_adminUser", $adminCreds.Password)
    $_adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString ($adminCreds.Password | ConvertFrom-SecureString)) ))
    

    $_sqlUser = $sqlCreds.UserName
    $_sqlPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString ($sqlCreds.Password | ConvertFrom-SecureString)) ))

    Node localhost
    {
       
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        DomainJoin DomainJoin
        {
            domainName = $domainName 
            adminCreds = $adminCreds 
        }
	
        #Install the IIS Role (for Izenda)
        WindowsFeature IIS 
        { 
            Ensure = “Present” 
            Name = “Web-Server”
           # IncludeAllSubFeature = $True 
        }
        
       Script DownloadSQLMSI
       {
            TestScript = {
                Test-Path "C:\SQLEXPR_x64_ENU.exe"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation+ "SQLEXPR_x64_ENU.exe")
                $dest = "C:\SQLEXPR_x64_ENU.exe"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadSQLMSI"}}      
        }
		
	   WindowsFeature installdotNet35 
	   {             
		    Ensure = "Present"
		    Name = "Net-Framework-Core"
		    Source = "\\neuromancer\Share\Sources_sxs\?Win2012R2"
	   }
       
       WindowsFeature ADDomainServices 
	   {             
		    Ensure = "Present"
		    Name = "AD-Domain-Services"
	   }
       
       Script ExtractSQLInstaller
       {
            TestScript = {
                Test-Path "C:\SQLEXPR_x64_ENU\"
            }
            SetScript ={
                $dest = "C:\SQLEXPR_x64_ENU.exe"
                $arguments = '/q /x:C:\SQLEXPR_x64_ENU'
                $exitCode = (Start-Process -Filepath "$dest" -ArgumentList "$arguments" -Wait -Passthru).ExitCode
            }
            GetScript = {@{Result = "ExtractSQLInstaller"}}      
        }

        xSqlServerInstall installSqlServer
        {
            InstanceName = $sqldatabase
            SourcePath = "C:\SQLEXPR_x64_ENU"
            Features= "SQLEngine"
            SqlAdministratorCredential = $sqlCreds
        }

	    Script DownloadGridMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectDataGrid_x64_WT.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectDataGrid_x64_WT.msi")
                $dest = "C:\EricomConnectDataGrid_x64_WT.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadGridMSI"}}
        }
		
        Package InstallGridMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectDataGrid_x64_WT.msi"
            Name = "Ericom Connect Data Grid"
            ProductId = "08CD0EA8-6E2D-43B5-BE12-9F0AAF6034EA"
            Arguments = ""
            LogPath = "C:\log-ecdg.txt"
            DependsOn = "[Script]DownloadGridMSI"
        }
	
	    Script DownloadProcessingUnitServerMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectProcessingUnitServer.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectProcessingUnitServer.msi")
                $dest = "C:\EricomConnectProcessingUnitServer.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadProcessingUnitServerMSI"}}

        }
		
        Package InstallProcessingUnitServerMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectProcessingUnitServer.msi"
            Name = "Ericom Connect Processing Unit Server"
            ProductId = "852CB2EC-F2C0-4F90-90DB-75E6A0A2733F"
            Arguments = ""
            LogPath = "C:\log-ecpus.txt"
            DependsOn = "[Script]DownloadProcessingUnitServerMSI"
        }


	    Script DownloadAdminWebServiceMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectAdminWebService.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectAdminWebService.msi")
                $dest = "C:\EricomConnectAdminWebService.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadAdminWebServiceMSI"}}
      
        }
		
        Package InstallAdminWebServiceMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectAdminWebService.msi"
            Name = "Ericom Connect Admin Web Service"
            ProductId = "F8E976A6-2267-459A-B518-448C33CFCA50"
            Arguments = ""
            LogPath = "C:\log-ecaws.txt"
            DependsOn = "[Script]DownloadAdminWebServiceMSI"
        }

        Package InstallEricomAnalyticsMSI
        {
            Ensure = "Present" 
            Path  = "C:\Program Files\Ericom Software\Ericom Connect Admin Web Service\Ericom Analytics.msi"
            Name = "Ericom Analytics"
            ProductId = "792FF3F1-4D55-437D-91A3-B07118A892CD"
            Arguments = ""
            LogPath = "C:\log-erbi.txt"
        }

	    Script DownloadClientWebServiceMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectClientWebService.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectClientWebService.msi")
                $dest = "C:\EricomConnectClientWebService.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadClientWebServiceMSI"}}
      
        }
		
        Package InstallClientWebServiceMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectClientWebService.msi"
            Name = "Ericom Connect Client Web Service"
            ProductId = "0755B3C8-38E7-447F-B465-F626A641C427"
            Arguments = ""
            LogPath = "C:\log-eccws.txt"
            DependsOn = "[Script]DownloadClientWebServiceMSI"
        }
        
        Script DownloadRemoteAgentWebServiceMSI
        {
            TestScript = {
                Test-Path "C:\EricomConnectRemoteAgentWebService.msi"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "EricomConnectRemoteAgentWebService.msi")
                $dest = "C:\EricomConnectRemoteAgentWebService.msi"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadRemoteAgentWebServiceMSI"}}
      
        }
        
        Package InstallRemoteAgentWebServiceMSI
        {
            Ensure = "Present" 
            Path  = "C:\EricomConnectRemoteAgentWebService.msi"
            Name = "Ericom Remote Agent Web Service"
            ProductId = "B1B38E5A-184D-4FF4-8988-AF30531D05B9"
            Arguments = ""
            LogPath = "C:\log-ecrws.txt"
            DependsOn = "[Script]DownloadRemoteAgentWebServiceMSI"
        }
        Script DownloadEricomAirZip
        {
            TestScript = {
                Test-Path "C:\SSO.zip"
            }
            SetScript ={
                $source = "https://raw.githubusercontent.com/ErezPasternak/azure-quickstart-templates/EricomConnect/EricomConnectDaaS752/SSO.zip"
                $dest = "C:\SSO.zip"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadEricomAirZip"}}
      
        }
        Script DownloadEricomDaaSService
        {
            TestScript = {
                Test-Path "C:\DaaSService.zip"
            }
            SetScript ={
                $_softwareBaseLocation = "$Using:softwareBaseLocation"
                $source = ($_softwareBaseLocation + "DaaSService.zip")
                $dest = "C:\DaaSService.zip"
                Invoke-WebRequest $source -OutFile $dest
            }
            GetScript = {@{Result = "DownloadEricomDaaSService"}}
		
        }
        
        Script DisableFirewallDomainProfile
        {
            TestScript = {
                return ((Get-NetFirewallProfile -Profile Domain).Enabled -eq $false)
            }
            SetScript = {
                Set-NetFirewallProfile -Profile Domain -Enabled False
            }
            GetScript = {@{Result = "DisableFirewallDomainProfile"}}
        }

        Script InitializeGrid
        {
            TestScript = {
                $isServiceRunning = $false;
                $allServices = Get-Service | Where { $_.DisplayName.StartsWith("Ericom")}
                foreach($service in $seallServicesrvices)
                {
                    if ($service.Name -contains "EricomConnectProcessingUnitServer") {
                        if ($service.Status -eq "Running") {
                            Write-Verbose "ECPUS service is running"
                            $isServiceRunning = $true;
                        } elseif ($service.Status -eq "Stopped") {
                            Write-Verbose "ECPUS service is stopped"
                            $isServiceRunning = $false;
                        } else {
                            $statusECPUS = $service.Status
                            Write-Verbose "ECPUS status: $statusECPUS"
                        }
                    }
                }
                return ($isServiceRunning -eq $true);
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
                # Call Configuration Tool
                Write-Verbose "Configuration step"
                $workingDirectory = "$env:ProgramFiles\Ericom Software\Ericom Connect Configuration Tool"
                $configFile = "EricomConnectConfigurationTool.exe"
                
                #$credentials = $Using:adminCreds;
                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                $_gridName = "$Using:gridName"
                $_hostOrIp = "$env:COMPUTERNAME"
                $_saUser = $Using:_sqlUser
                $_saPass = $Using:_sqlPassword
                $_databaseServer = $Using:sqlserver
                $_databaseName = $Using:sqldatabase
                $_externalFqdn = $Using:externalFqdn

                $configPath = Join-Path $workingDirectory -ChildPath $configFile
                
                Write-Verbose "Configuration mode: without windows credentials"
                $arguments = " NewGrid /AdminUser `"$_adminUser`" /AdminPassword `"$_adminPass`" /GridName `"$_gridName`" /SaDatabaseUser `"$_saUser`" /SaDatabasePassword `"$_saPass`" /DatabaseServer `"$_databaseServer\$_databaseName`" /disconnect /noUseWinCredForDBAut"
                
                $baseFileName = [System.IO.Path]::GetFileName($configPath);
                $folder = Split-Path $configPath;
                cd $folder;
                Write-Verbose "$configPath $arguments"
                $exitCode = (Start-Process -Filepath $configPath -ArgumentList "$arguments" -Wait -Passthru).ExitCode
                
                if ($exitCode -eq 0) {
                    Write-Verbose "Ericom Connect Grid Server has been succesfuly configured."
                } else {
                    Write-Verbose ("Ericom Connect Grid Server could not be configured. Exit Code: " + $exitCode)
                }
            }
            GetScript = {@{Result = "InitializeGrid"}}      
        }
      
        Script UnZipAir
        {
            TestScript = {
                Test-Path "C:\Program Files\Ericom Software\Ericom Connect Client Web Service\WebServer\AirSSO\"
            }
            SetScript ={
                $source = "C:\SSO.zip"
                Unblock-File -Path "C:\SSO.zip"
                $destTmp = "C:\Program Files\Ericom Software\Ericom Connect Client Web Service\WebServer\"
                $dest = "C:\Program Files\Ericom Software\Ericom Connect Client Web Service\WebServer\AirSSO\"
                $shell = new-object -com shell.application
                $zip = $shell.NameSpace($source)
                foreach($item in $zip.items())
                {
                    $shell.Namespace($destTmp).copyhere($item)
                }
                Move-Item "$destTmp\SSO" -Destination $dest -Force -ErrorAction SilentlyContinue
            }
            GetScript = {@{Result = "UnZipAir"}}
        }
        
        Script UnZipDaaSService
        {
            TestScript = {
                Test-Path "C:\Program Files\Ericom Software\Ericom DaaS Service\"
            }
            SetScript ={
                $source = "C:\DaaSService.zip"
                Unblock-File -Path "C:\DaaSService.zip"
                $destTmp = "C:\Program Files\Ericom Software\Ericom DaaS Service"
                $dest = "C:\Program Files\Ericom Software\Ericom DaaS Service\"
                $shell = new-object -com shell.application
                $zip = $shell.NameSpace($source)
                
                New-Item -ItemType Directory -Path $destTmp -Force -ErrorAction SilentlyContinue 
                foreach($item in $zip.items())
                {
                    $shell.Namespace($destTmp).copyhere($item)
                }
     
            }
            GetScript = {@{Result = "UnZipDaaSService"}}
        }
        
        Script InstallDaaSService
        {
            TestScript = {
                return $false
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
               
                Write-Verbose "DaaSService Configuration step"
                $workingDirectory = "C:\Program Files\Ericom Software\Ericom DaaS Service\"
                $ServiceName = "AutomationWebService.exe"                  
                $ServicePath = Join-Path $workingDirectory -ChildPath $ServiceName
                
                # register the service
                $argumentsService = "/install";
                
                $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
                if ($exitCodeCli -eq 0) {
                    Write-Verbose "DaaSService: Service has been succesfuly registerd."
                } else {
                    Write-Verbose "$ServicePath $argumentsService"
                    Write-Verbose ("DaaSService: Service could not be registerd.. Exit Code: " + $exitCode)
                } 
            }
            GetScript = {@{Result = "InstallDaaSService"}}
        }
        
        Script CopyRecursiveFolder
        {
            TestScript = {
                return $false
            }
            SetScript = {
                $DestDirectory = "C:\Program Files\Ericom Software\Ericom DaaS Service\"
                $FromDirectory = "$env:ProgramFiles\Ericom Software\Ericom Connect Configuration Tool\*"
                Copy-Item $FromDirectory $DestDirectory -recurse -force
            }
            GetScript = {@{Result = "SetRDA"}}
        }
        
        Script ConfigureDaaSService
        {
            TestScript = {
                return $false
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                $_gridName = "$Using:gridName"
                $_hostOrIp = "$env:COMPUTERNAME"
                $_saUser = $Using:_sqlUser
                $_saPass = $Using:_sqlPassword
                $_databaseServer = $Using:sqlserver
                $_databaseName = $Using:sqldatabase
                $_externalFqdn = $Using:externalFqdn
                $baseRDPGroup = $Using:baseADGroupRDP
                $rdshpattern = $Using:remoteHostPattern
                $emailTemplate = "WebServer\DaaS\emails\ready.html"
                $SMTPServer = "ericom-com.mail.protection.outlook.com"
                $SMTPPort = "25"
                $SMTPFrom = "daas@ericom.com"
                $SMTPUser = "daas@ericom.com"
                $SMTPPassword = "1qaz@Wsx#"
                $BCCList = "erez.pasternak@ericom.com"

                $portNumber = 2244; # DaaS WebService port number
               
                Write-Verbose "DaaSService Configuration step"
                $workingDirectory = "C:\Program Files\Ericom Software\Ericom DaaS Service\"
                $ServiceName = "AutomationWebService.exe"                  
                $ServicePath = Join-Path $workingDirectory -ChildPath $ServiceName

                $fqdn = "PortalSettings/FQDN $_externalFqdn";
                $port = "PortalSettings/Port $portNumber";
                $adDomain = "ADSettings/Domain $domainName";
                $adAdmin = "ADSettings/Administrator $_adminUser";
                $adPassword = "ADSettings/Password $_adminPass";
                $adBaseGroup = "ADSettings/BaseADGroup $baseRDPGroup";
                $rhp = "ADSettings/RemoteHostPattern $rdshpattern";
                $ec_admin = "ConnectSettings/EC_AdminUser $_adminUser"; # EC_Admin User
                $ec_pass = "ConnectSettings/EC_AdminPass $_adminPass"; # EC_Admin Pass
                $RDCB_GridName = "ConnectSettings/EC_GridName $_gridName"; # RDCB info - gridname
                $run_boot_strap = "appSettings/LoadBootstrapData False"; # Run bootstrap code
               
                $MAilTemplate = "EmailSettings/EmailTemplatePath $emailTemplate";
                $MAilServer   = "EmailSettings/SMTPServer $SMTPPort";
                $MAilPort = "EmailSettings/SMTPPort $SMTPPort";
                $MAilFrom = "EmailSettings/SMTPFrom $SMTPFrom";
                $MAilUser = "EmailSettings/SMTPUsername $SMTPUser";
                $MAilPassword = "EmailSettings/SMTPPassword $SMTPPassword";
                $MAilBCC = "EmailSettings/ListOfBcc $BCCList";
                
                 
                # register the service
                $argumentsService = "/changesettings $fqdn $port $adDomain $adAdmin $adPassword $adBaseGroup $rhp $ec_admin $ec_pass $run_boot_strap $RDCB_GridName $MAilTemplate $MAilServer $MAilPort $MAilFrom $MAilUser $MAilPassword $MAilBCC";
                
                $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
                if ($exitCodeCli -eq 0) {
                    Write-Verbose "DaaSService: Service has been succesfuly updated."
                } else {
                    Write-Verbose "$ServicePath $argumentsService"
                    Write-Verbose ("DaaSService: Service could not be updated.. Exit Code: " + $exitCode)
                } 
            }
            GetScript = {@{Result = "ConfigureDaaSService"}}
        }
        
        Script StartDaaSService
        {
            TestScript = {
                return $false
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
               
                Write-Verbose "DaaSService Configuration step"
                $workingDirectory = "C:\Program Files\Ericom Software\Ericom DaaS Service\"
                $ServiceName = "AutomationWebService.exe"                  
                $ServicePath = Join-Path $workingDirectory -ChildPath $ServiceName
                
                # register the service
                $argumentsService = "/start";
                
                $exitCodeCli = (Start-Process -Filepath $ServicePath -ArgumentList "$argumentsService" -Wait -Passthru).ExitCode;
                if ($exitCodeCli -eq 0) {
                    Write-Verbose "DaaSService: Service has been succesfuly registerd."
                } else {
                    Write-Verbose "$ServicePath $argumentsService"
                    Write-Verbose ("DaaSService: Service could not be registerd.. Exit Code: " + $exitCode)
                } 
            }
            GetScript = {@{Result = "StartDaaSService"}}
        }
        Script AlterAirURLPage
        {
            TestScript = {
                return $false
            }
            SetScript ={
                $domainSuffix = "@" + $Using:domainName;
                # Call Configuration Tool
                Write-Verbose "Configuration step"
                $workingDirectory = "$env:ProgramFiles\Ericom Software\Ericom Connect Configuration Tool"
                $newAirURL = "AirSSO/AccessSSO.htm"
                $connectCli = "ConnectCli.exe"                  

                $_adminUser = "$Using:_adminUser" + "$domainSuffix"
                $_adminPass = "$Using:_adminPassword"
                
                $cliPath = Join-Path $workingDirectory -ChildPath $connectCli
                
                # publish admin page via EuwsConfig
                $argumentsCli = "EuwsConfig /adminUser `"$_adminUser`" /adminPassword `"$_adminPass`" common DefaultUrl=$newAirURL";
                
                $exitCodeCli = (Start-Process -Filepath $cliPath -ArgumentList "$argumentsCli" -Wait -Passthru).ExitCode;
                if ($exitCodeCli -eq 0) {
                    Write-Verbose "EuwsConfig: Air page has been succesfuly published."
                } else {
                    Write-Verbose "$cliPath $argumentsCli"
                    Write-Verbose ("EuwsConfig: Air page could not be published.. Exit Code: " + $exitCode)
                } 
            }
            GetScript = {@{Result = "AlterAirURLPage"}}
        }
    }
}