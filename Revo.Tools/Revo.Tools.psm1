function Import-RevoCertificate{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$CertificateLocation,
        [ValidateNotNull()]
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [securestring]$CertificatePassword,
        [parameter(Mandatory=$true)]
        [ValidateSet("CurrentUser","LocalMachine", IgnoreCase = $true)]
        [string]$StoreType
    )
    begin{
        if(!$env:windir){
            Write-Warning "Currently Linux systems only supports CurrentUser Store"
            $StoreType = "CurrentUser"
        }
    }
    process{
        $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::My 
        $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreType 
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation) 
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) 
        $Flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable 
        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateLocation,$CertificatePassword,$Flag) 
        $Store.Add($Certificate) 
    }
    end{
        return $Certificate
        $Store.Close() 
    }
}

function Get-RevoCertificates{
    param(
        [parameter(Mandatory=$true)]
        [ValidateSet("CurrentUser","LocalMachine", IgnoreCase = $true)]
        [string]$StoreType
    )
    begin{
        if(!$env:windir){
            Write-Warning "Currently Linux systems only supports CurrentUser Store"
            $StoreType = "CurrentUser"
        }
    }
    process{
        $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::My 
        $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreType 
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation) 
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly) 
    }
    end{
        return $Store.Certificates
        $Store.Close() 
    }
}

function New-RevoHash{
    param(
        [parameter(Mandatory=$true)]
        [string]$Value
    )
    begin{

    }
    process{
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($TableInformation))
        $hashString = [System.BitConverter]::ToString($hash)
    }
    end{
        return $hashString.Replace('-', '')
    }
}