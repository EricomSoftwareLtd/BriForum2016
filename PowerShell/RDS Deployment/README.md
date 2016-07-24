![Ericom::Access Done Right](http://www.ericom.com/imgs/home/EricomLogo2.jpg "Ericom Logo") 

### This folder contains deployment powershell scripts:

##### AWSConnectionBroker.ps1

This script will create a RDS connetion broker as part of a multi machine environment , it will verify Windows configuration and will update it if needed
It will create a new RDS collection, install several applicaiton and publish them as RemoteApp, this script update windows event log with any failure of success, 
and also can send a mail on severe errors

##### AWSRemoteDesktopSessionHost.ps1 

This script will create a RDS Session Host as part of a multi machine environment , it will verify Windows configuration and will update it if needed
It will add itself to an existing Connection Broker, install several applicaiton and publish them as RemoteApp, this script update windows event log with any failure of success, 
and also can send a mail on severe errors

##### RDSDSC

This PowerShell DSC is used to deploy multi machine RDS deployment