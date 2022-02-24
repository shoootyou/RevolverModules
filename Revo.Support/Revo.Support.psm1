function Import-RevoCertificate{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$CertificateLocation,
        [ValidateNotNull()]
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [securestring]$CertificatePassword
    )
    begin{

    }
    process{
        $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::My 
        $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser 
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
