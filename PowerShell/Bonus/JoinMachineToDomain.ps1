param(
    $domain,
    $username,
    $password
)

$domain = "myDomain"
$password = "myPassword!" | ConvertTo-SecureString -asPlainText -Force
$username = "$domain\myUserAccount" 
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -Credential $credential