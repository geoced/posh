<#
.SYNOPSIS
Find a certificate in the local certificate store

.DESCRIPTION
Different parameters can be supplied to find the certificate in the local certificate store.
All certificate locations are parsed. If several certificates match the search criteria, all are returned.
#>
function Find-Certificate {
    [CmdletBinding(DefaultParameterSetName = 'Thumbprint')]

    param (
        # An X509Certificate2 object to look for in the local certificate store
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        # The thumbprint of the certificate to look for
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Thumbprint')]
        [string[]] $Thumbprint,

        # The subject of the certificate to look for
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Subject')]
        [string[]] $Subject,

        # The issuer of the certificate to look for
        [Parameter(Mandatory, ParameterSetName = 'Issuer')]
        [string[]] $Issuer
    )
    
    begin {
        try {
            $storedCerts = Get-ChildItem -Path Cert:\ -Recurse -ErrorAction SilentlyContinue
        } catch {}
    }
    
    process {
        $matchingCerts = @()

        if ($Certificate) {
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            [void] $chain.Build($Certificate)
            foreach ($chainElement in $chain.ChainElements) {
                $matchingCerts += $storedCerts | Where-Object { $_ -eq $chainElement.Certificate }
            }

        } elseif ($Thumbprint) {
            $matchingCerts = $storedCerts | Where-Object Thumbprint -In $Thumbprint

        } elseif ($Subject) {
            foreach ($sub in $Subject) {
                $matchingCerts += $storedCerts | Where-Object Subject -Match $sub
            }

        } elseif ($Issuer) {
            foreach ($iss in $Issuer) {
                $matchingCerts += $storedCerts | Where-Object Issuer -Match $iss
            }
        }
    }
    
    end {
        foreach ($matchingCert in $matchingCerts) {
            Write-Verbose -Message "Found matching certificate at $(($matchingCert.PSPath -split '::')[-1]) ($($matchingCert.Subject))"
        }
        $matchingCerts
    }
}

<#
.SYNOPSIS
Download a public certificate

.DESCRIPTION
Download a public certificate from a local or remote server and returns it as an X509Certificate2 object
#>
function Get-PublicCertificate {
    [CmdletBinding()]

    param (
        # Host name or FQDN to connect to
        [Parameter(Mandatory)]
        [string] $ComputerName,

        # Port number to connect to. 443 (HTTPS) by default.
        [uint16] $Port = 443,

        # Server Name Indication
        [string] $SNI = ''
    )

    $certificate = $null
    $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

    try {
        $tcpClient.Connect($ComputerName, $Port)
        $tcpStream = $tcpClient.GetStream()
        $callback = { param($sender, $cert, $chain, $errors) return $true }
        $sslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($tcpStream, $true, $callback)

        try {
            $sslStream.AuthenticateAsClient($SNI)
            $certificate = $sslStream.RemoteCertificate
        } finally {
            $sslStream.Dispose()
        }
    } finally {
        $tcpClient.Dispose()
    }

    if ($certificate) {
        if ($certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate
        }
        return $certificate
    } else {
        Write-Message -Type Warning "No certificate found at ${ComputerName}:$Port"
    }
}

<#
.SYNOPSIS
Converts an end-entity certificate to a chained certificate

.DESCRIPTION
Converts a single end-entity certificate to a full chain of intermediary certificates all the way to a trusted root Certificate Authority.

.NOTES
Servers are supposed to present their own certificate as well as all intermediate certificates on the path to a trusted root Certificate Authority.
The root certificate is not required. Including it is inefficient as it increases the size of the SSL handshake.
#>
function ConvertTo-CertificateChain {
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]

    param (
        # The source certificate to convert
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        # The file path of the certificate to convert
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'SourceFilePath')]
        [string] $SourceFilePath,

        # An optional file path where to write the chained certificate
        [string] $ExportPath,

        # Whether to include the root CA in the exported chained certificate
        [switch] $IncludeRoot
    )
    
    process {
        if ($SourceFilePath) {
            $Certificate = if (Test-Path -Path $SourceFilePath) {
                $file = Get-Item -Path $SourceFilePath
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($file.FullName)
            } else {
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                    ([System.IO.FileNotFoundException] "Could not find certificate file `"$SourceFilePath`""),
                        'PathNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $SourceFilePath)
                )
            }
        }

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        [void] $chain.Build($Certificate)

        if ($ExportPath) {
            Remove-Item -Path $ExportPath -Force -ErrorAction SilentlyContinue
            for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
                if (!$IncludeRoot -and $i -eq ($chain.ChainElements.Count - 1)) {
                    break
                }
                ConvertTo-PemCertificate -Certificate $chain.ChainElements[$i].Certificate -ExportPath $ExportPath -Append
            }
        } else {
            return $chain.ChainElements.Certificate
        }
    }
}

<#
.SYNOPSIS
Convert a certiticate to the PEM format

.DESCRIPTION
The PEM format is a Base64 ASCII string divided in 64-char long substrings and sandwiched between a standardized header and footer.
#>
function ConvertTo-PemCertificate {
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]

    param (
        # The source certificate to convert
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        # The file path of the certificate to convert
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'SourceFilePath')]
        [string] $SourceFilePath,

        # An optional file path where to write the PEM certificate
        [string] $ExportPath,

        # If a file at ExportPath already exists, append the PEM certificate to the same file.
        [switch] $Append
    )

    process {
        if ($SourceFilePath) {
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($SourceFilePath)
        }

        $base64String = [System.Convert]::ToBase64String($Certificate.GetRawCertData())

        if ($ExportPath) {
            $base64String = ($base64String -split '(.{64})' | Where-Object { $_ }) -join "`n"
            $params = @{
                Path     = $ExportPath
                Value    = "-----BEGIN CERTIFICATE-----`n$base64String`n-----END CERTIFICATE-----`n"
                Encoding = 'ASCII'
                Force    = $true
                NoNewline = $true
            }
            if ($Append) {
                Add-Content @params
            } else {
                Set-Content @params
            }
        } else {
            return $base64String
        }
    }
}
