# posh
A bunch of PowerShell cmdlets I find useful in my day-to-day activities

## Certificates.ps1

### Find-Certificate
Find a certificate in the local certificate store

### Get-PublicCertificate
Download a public certificate from a local or remote server and returns it as an X509Certificate2 object

### ConvertTo-CertificateChain
Converts a single end-entity certificate to a full chain of intermediary certificates all the way to a trusted root Certificate Authority

### ConvertTo-PemCertificate
Convert a certiticate to the PEM format
