function Import-RevoCertificate{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$CertificateLocation,
        [ValidateNotNull()]
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [securestring]$CertificatePassword,
        [parameter(Mandatory=$false)]
        [ValidateSet("CurrentUser","LocalMachine", IgnoreCase = $true)]
        [string]$StoreType
    )
    begin{

    }
    process{
        $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::My 
        $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreType 
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation) 
        $Flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable 
        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateLocation,$CertificatePassword,$Flag) 
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) 
        $Store.Add($Certificate) 
        $Store.Close() 
    }
    end{

    }
}
