<#
    .DESCRIPTION
        Accesses a SSL Certificate from Azure KeyVault and applies it to a Web App SSL binding

    .PARAMETER KeyvaultName
        The name of the Azure Keyvault that you want the certificate to be stored in
    
    .PARAMETER WebAppName
        The name of the Web App that you're wanting to apply the certificate to
    
    .PARAMETER WebAppResourceGroup
        The resource group name that the Web App belongs to

    .PARAMETER domain
        The FQDN of the domain.  The custom domain should already be added to the Web App.

    .NOTES
        AUTHOR: Gordon Byers
        LASTEDIT: June 4, 2018
#>

param(
    [parameter(Mandatory=$true)]
    [String]$keyvaultName,
    [parameter(Mandatory=$true)]
	[String] $WebAppName,
    [parameter(Mandatory=$true)]
	[String] $WebAppResourceGroup,
    [parameter(Mandatory=$true)]
	[String] $domain = "Eg westeurope4.azdemo.co.uk"
)

$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

function CreateRandomPassword() {
    Write-Host "Creating random password"
    $bytes = New-Object Byte[] 32
    $rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rand.GetBytes($bytes)
    $rand.Dispose()
    $password = [System.Convert]::ToBase64String($bytes)
    return $password
}

#Clean up the domain name
$certificateName=$domain.replace(".","")
    
#Find the Web App
$webapp = Get-AzureRmWebApp -ResourceGroupName $WebAppResourceGroup -Name $WebAppName

#Get the certificate out of Keyvault
$kvSecret = Get-AzureKeyVaultSecret -VaultName $keyvaultName -Name $certificateName
Write-Output "Certificate last updated : $($kvSecret.Updated)"
$kvSecretBytes = [System.Convert]::FromBase64String($kvSecret.SecretValueText)
$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$certCollection.Import($kvSecretBytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
$password = CreateRandomPassword
$protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password)
$pfxPath = "$certificateName.pfx"
[System.IO.File]::WriteAllBytes($pfxPath, $protectedCertificateBytes)

#Apply the certificate to the web app
New-AzureRmWebAppSSLBinding -WebApp $webapp -Name $domain -certificatefilepath $pfxPath -certificatepassword $password -SslState SniEnabled
Write-Output "WebApp Certificate SSL binding updated"

#cleanup
[System.IO.File]::Delete($pfxPath)