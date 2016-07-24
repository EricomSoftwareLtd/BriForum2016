![Ericom::Access Done Right](http://www.ericom.com/imgs/home/EricomLogo2.jpg "Ericom Logo") 

### Deploy **Ericom Connect 7.5.1 ** on a Multiple Virtual Machines Environment

[![Deploy to Azure](http://azuredeploy.net/deploybutton.png)](https://azuredeploy.net/)

##### This template deploys the following resources:

* Storage account;
* Vnet, public ip, load balancer;
* Domain controller vm;
* Ericom Connect Gateway;
* Ericom Connect Grid;
* A number of RD Session hosts (number defined by *'numberOfRdshInstances'* parameter);

**The template will deploy a domain controller, join all VMs to the new domain, configure each Windows VM and then setup and configure Ericom Connect.**

* [Additional information on Ericom Connect](http://www.ericom.com/connect-enterprise.asp)

* [Ericom Connect Online Guide](https://www.ericom.com/communities/guide/home/connect-7-5-0)

[![Visualize](http://armviz.io/visualizebutton.png "Visualize")](http://armviz.io/#/?load=https://raw.githubusercontent.com/ErezPasternak/azure-quickstart-templates/EricomConnect/EricomConnect7511/azuredeploy.json)
