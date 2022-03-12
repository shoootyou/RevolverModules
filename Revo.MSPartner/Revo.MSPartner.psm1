function New-RevoPartnerAccess{
    param(
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [parameter(Mandatory=$false, ParameterSetName = "UserAuthentication")]
        [string]$TenantID,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$ClientID,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$CertificateLocation,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [securestring]$CertificatePassword,
        [parameter(Mandatory=$false, ParameterSetName = "ServicePrincipal")]
        [switch]$SecureOutput
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{

        $Module = Get-Module -Name MSAL.PS -ListAvailable
        if($null -eq $Module){
            Install-Module -Name MSAL.PS -Scope CurrentUser -Force -Confirm:$false;
            Import-Module -Name MSAL.PS -Scope CurrentUser
        }
        else{
            Import-Module -Name MSAL.PS -Scope CurrentUser
        }

        $CerLocValidation = Test-Path -Path $CertificateLocation -ErrorAction SilentlyContinue

        if(!$CerLocValidation){
            $CertLocationInvalid = $true
        }
        else {
            $ErrorActionPreference = 'SilentlyContinue'
            $Flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable 
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateLocation,$CertificatePassword,$Flag)
            if($Certificate){
                $ParseInformation = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -ClientCertificate $Certificate -Scopes 'https://graph.windows.net/.default'   
            }
            else {
                $CertPasswordInvalid = $true
            }

        }
        
    }
    end{
        $ErrorActionPreference = "Continue"
        if($CertLocationInvalid){
            Write-Error "Can't find the certificate. Please check your path."
        }
        elseif ($CertPasswordInvalid) {
            Write-Error "Certificate password incorrect. Please check the value."
        }
        else{
            New-Variable -Name "RevoPartnerBearerToken" -Value ($ParseInformation.TokenType + " " + $ParseInformation.AccessToken) -Scope Global -Force -ErrorAction SilentlyContinue
            New-Variable -Name "RevoPartnerBearerTokenDetails" -Value $ParseInformation -Scope Global -Force -ErrorAction SilentlyContinue
            if(!$SecureOutput){
                Return $ParseInformation.TokenType + " " + $ParseInformation.AccessToken
            }
        }
    }
}

function Get-RevoPartnerResources{
    param(
        [parameter(Mandatory=$true, ParameterSetName = "Predefined")]
        [ValidateSet("Customers","PartnerProfile", IgnoreCase = $true)]
        [string]$Resource,
        [parameter(Mandatory=$true, ParameterSetName = "Custom")]
        [string]$CustomURL
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $BaseURL = "https://api.partnercenter.microsoft.com/v1"

        if($CustomURL){
            $ResourceURL = $CustomURL
        }
        else {
            switch ($Resource) {
                Customers { $ResourceURL = "/customers" }
                PartnerProfile { $ResourceURL = "/profiles/mpn" }
                Default { $ResourceURL = "/profiles/mpn" }
            }
        }

        $FinalURL = ($BaseURL + $ResourceURL)

        $AccessToken = Get-Variable -Name "RevoPartnerBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)
            $Headers.Add("Accept","application/json")
            $Headers.Add("X-Locale","es-PE")
    
            $WebRequest = Invoke-WebRequest -Method Get -Uri $FinalURL -Headers $Headers -ErrorVariable InvokeError

            if ($InvokeError.Count -gt 0) {
                if($InvokeError.ErrorRecord.ToString() -like "This resource can't be accessed by application credentials."){
                    $BearerNotAuthorized = $true
                }
                else{
                    switch(($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).error.code){
                        'ExpiredAuthenticationToken' {
                            $BearerTokenExpired = $true
                        }
                        'AuthenticationFailedInvalidHeader'{
                            $BearerTokenInvalidHeader  = $true
                        }
                        'AuthenticationFailed'{
                            $BearerTokenFailed  = $true
                        }
                        default {
                            $BearerTokenError = $true
                        }
                    }
                }

            }
            else {
                if($WebRequest){
                    if ($WebRequest.Content[0] -ne '{') {
                        $Output = $WebRequest.Content.Substring(1) | ConvertFrom-Json -Depth 10
                    }
                    else {
                        $Output = $WebRequest.Content | ConvertFrom-Json -Depth 10
                    }
                }
                
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerNotAuthorized){
            Write-Error "This resource can't be accessed by application credentials. Try something diferent or use another credentials."
        }
        elseif($BearerTokenFailed){
            Write-Error "Your bearer token was invalid, please reconnect with New-RevoPartnerAccess"
        }
        elseif ($BearerTokenInvalidHeader) {
            Write-Error "Your bearer token was malformed, please reconnect with New-RevoPartnerAccess"
        }
        elseif ($BearerTokenExpired) {
            Write-Error "Your bearer token was expired, please reconnect with New-RevoPartnerAccess"
        }
        elseif($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoPartnerAccess"
        }
        else{
            Return $Output
        }
    }
}