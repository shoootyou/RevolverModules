function New-RevoPartnerAccess{
    param(
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$TenantID,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$ClientID,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$CertificateLocation,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [securestring]$CertificatePassword,
        [parameter(Mandatory=$false, ParameterSetName = "ServicePrincipal")]
        [switch]$SecureOutput,
        [parameter(Mandatory=$false, ParameterSetName = "ServicePrincipal")]
        [switch]$ForceRefresh,
        [parameter(Mandatory=$false, ParameterSetName = "ServicePrincipal")]
        [switch]$ClearToken
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
        
        if($ClearToken){
            Remove-Variable -Name RevoPartnerBearerToken -Force -ErrorAction SilentlyContinue
            Remove-Variable -Name RevoPartnerBearerTokenDetails -Force -ErrorAction SilentlyContinue
            Clear-MsalTokenCache -ErrorAction SilentlyContinue
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
                $BearerValue = Get-Variable -Name "RevoPartnerBearerToken" -ValueOnly -ErrorAction SilentlyContinue
                if($ForceRefresh -and $BearerValue){
                    $ParseInformation = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -ClientCertificate $Certificate -Scopes 'https://graph.windows.net/.default' -ForceRefresh
                }
                else{
                    $ParseInformation = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -ClientCertificate $Certificate -Scopes 'https://graph.windows.net/.default'
                }
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
        [ValidateSet("Customers","PartnerProfile", "Subscriptions", IgnoreCase = $true)]
        [string]$Resource,
        [parameter(Mandatory=$true, ParameterSetName = "Custom")]
        [string]$CustomURL,
        [parameter(ParameterSetName = "Predefined")]
        [ValidateScript({$Resource -eq 'Subscriptions'},ErrorMessage = "CustomerID parameters it's only available on Subscriptions resource.")]
        [ValidatePattern('^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$',ErrorMessage = "CustomerID must be the GUID of the Customer Tenant ID.")]
        [string]$CustomerID
        
    )
    begin{
        $ErrorActionPreference = "Stop"
        if($Resource -eq 'Subscriptions' -and !$CustomerID){
            Write-Error "Customer Tenant Id must be send by parameter CustomerID. Please validate and try again."
            break
        }
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
                Subscriptions { $ResourceURL = "/customers/$CustomerID/subscriptions" }
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
                    $ModuleError = "This resource can't be accessed by application credentials. Try something diferent or use another credentials."
                }
                elseif ($InvokeError.ErrorRecord.ErrorDetails) {
                    switch(($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).code){
                        20002 { $ModuleError = ($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).description }
                        403 { $ModuleError = ($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).description }
                        default { $ModuleError = "Cannot access to the resource. Please try with other resource." }
                    }
                }
                else{
                    switch(($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).error.code){
                        'ExpiredAuthenticationToken' {
                            $ModuleError = "Your bearer token was expired, please reconnect with New-RevoPartnerAccess"
                        }
                        'AuthenticationFailedInvalidHeader'{
                            $ModuleError = "Your bearer token was malformed, please reconnect with New-RevoPartnerAccess"
                        }
                        'AuthenticationFailed'{
                            $ModuleError = "Your bearer token was invalid, please reconnect with New-RevoPartnerAccess"
                        }
                        default {
                            $ModuleError = "Cannot get the bearer token, please first connect by New-RevoPartnerAccess"
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
            $ModuleError = "Cannot get the bearer token, please first connect by New-RevoPartnerAccess"
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($ModuleError){
            Write-Error $ModuleError
        }
        else{
            Return $Output
        }
    }
}