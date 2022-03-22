function New-RevoPartnerAccess {
    param(
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [string]$TenantID,
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [string]$ClientID,
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [string]$CertificateLocation,
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [securestring]$CertificatePassword,
        [parameter(Mandatory = $false, ParameterSetName = "ServicePrincipal")]
        [switch]$SecureOutput,
        [parameter(Mandatory = $false, ParameterSetName = "ServicePrincipal")]
        [switch]$ForceRefresh,
        [parameter(Mandatory = $false, ParameterSetName = "ServicePrincipal")]
        [switch]$ClearToken
    )
    begin {
        $ErrorActionPreference = "SilentlyContinue"

    }
    process {

        $Module = Get-Module -Name MSAL.PS -ListAvailable
        if ($null -eq $Module) {
            Install-Module -Name MSAL.PS -Scope CurrentUser -Force -Confirm:$false;
            Import-Module -Name MSAL.PS -Scope CurrentUser
        }
        else {
            Import-Module -Name MSAL.PS -Scope CurrentUser
        }
        
        if ($ClearToken) {
            Remove-Variable -Name RevoPartnerBearerToken -Force -ErrorAction SilentlyContinue
            Remove-Variable -Name RevoPartnerBearerTokenDetails -Force -ErrorAction SilentlyContinue
            Clear-MsalTokenCache -ErrorAction SilentlyContinue
        }

        $CerLocValidation = Test-Path -Path $CertificateLocation -ErrorAction SilentlyContinue

        if (!$CerLocValidation) {
            $CertLocationInvalid = $true
        }
        else {
            $ErrorActionPreference = 'SilentlyContinue'
            $Flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable 
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateLocation, $CertificatePassword, $Flag)
            if ($Certificate) {
                $BearerValue = Get-Variable -Name "RevoPartnerBearerToken" -ValueOnly -ErrorAction SilentlyContinue
                if ($ForceRefresh -and $BearerValue) {
                    $ParseInformation = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -ClientCertificate $Certificate -Scopes 'https://graph.windows.net/.default' -ForceRefresh
                }
                else {
                    $ParseInformation = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -ClientCertificate $Certificate -Scopes 'https://graph.windows.net/.default'
                }
            }
            else {
                $CertPasswordInvalid = $true
            }

        }
        
    }
    end {
        $ErrorActionPreference = "Continue"
        if ($CertLocationInvalid) {
            Write-Error "Can't find the certificate. Please check your path."
        }
        elseif ($CertPasswordInvalid) {
            Write-Error "Certificate password incorrect. Please check the value."
        }
        else {
            New-Variable -Name "RevoPartnerBearerToken" -Value ($ParseInformation.TokenType + " " + $ParseInformation.AccessToken) -Scope Global -Force -ErrorAction SilentlyContinue
            New-Variable -Name "RevoPartnerBearerTokenDetails" -Value $ParseInformation -Scope Global -Force -ErrorAction SilentlyContinue
            if (!$SecureOutput) {
                Return $ParseInformation.TokenType + " " + $ParseInformation.AccessToken
            }
        }
    }
}

function New-RevoPartnerAccessByToken {
    param(
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [string]$ClientID,
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [string]$ResponseToken,
        [parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
        [string]$RefreshToken,
        [parameter(Mandatory = $false, ParameterSetName = "ServicePrincipal")]
        [switch]$SecureOutput,
        [parameter(Mandatory = $false, ParameterSetName = "ServicePrincipal")]
        [string]$TenantID
    )
    begin {
        $ErrorActionPreference = "SilentlyContinue"

    }
    process {

        if ($TenantID) {
            $Internal_AuthHost = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        }
        else {
            $Internal_AuthHost = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        }
        $Internal_ContentType = 'application/x-www-form-urlencoded'
        $Internal_Body = "client_id=$ENV:HS_AppId&scope=https://api.partnercenter.microsoft.com/user_impersonation%20offline_access&code=$ENV:HS_ResponseToken&grant_type=refresh_token&refresh_token=$ENV:HS_RefreshToken"
        $Internal_AccessToken = Invoke-WebRequest -Uri $Internal_AuthHost -ContentType $Internal_ContentType -Method POST -Body $Internal_Body
        $ParseInformation = ($Internal_AccessToken.Content | ConvertFrom-Json) 
        
    }
    end {
        $ErrorActionPreference = "Continue"
        New-Variable -Name "RevoPartnerBearerToken" -Value ($ParseInformation.token_type + " " + $ParseInformation.access_token) -Scope Global -Force -ErrorAction SilentlyContinue
        New-Variable -Name "RevoPartnerBearerTokenDetails" -Value $ParseInformation -Scope Global -Force -ErrorAction SilentlyContinue
        if (!$SecureOutput) {
            Return $ParseInformation.token_type + " " + $ParseInformation.access_token
        }
    }
}

function Get-RevoPartnerResources {
    param(
        [parameter(Mandatory = $true, ParameterSetName = "Predefined")]
        [parameter(Mandatory = $true, ParameterSetName = "Subscriptions")]
        [parameter(Mandatory = $true, ParameterSetName = "RoleMember")]
        [parameter(Mandatory = $true, ParameterSetName = "InvoiceDownload")]
        [parameter(Mandatory = $true, ParameterSetName = "InvoiceLineItems")]
        [ValidateSet(
            "Customers",
            "PartnerProfile",
            "Subscriptions",
            "SupportProfile",
            "Organization",
            "ResellerRequestLink",
            "Roles",
            "RoleMember",
            "Invoices",
            "InvoiceDownload",
            "InvoiceLineItems", IgnoreCase = $true)]
        [string]$Resource,
        [parameter(Mandatory = $true, ParameterSetName = "Custom")]
        [string]$CustomURL,
        [parameter(Mandatory = $true, ParameterSetName = "Subscriptions")]
        [ValidateScript({ $Resource -eq 'Subscriptions' }, ErrorMessage = "CustomerID parameters it's only available on Subscriptions resource.")]
        [ValidatePattern('^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$', ErrorMessage = "CustomerID must be the GUID of the Customer Tenant ID.")]
        [string]$CustomerID,
        [parameter(Mandatory = $true, ParameterSetName = "RoleMember")]
        [ValidateScript({ $Resource -eq 'RoleMember' }, ErrorMessage = "RoleID parameters it's only available on RoleMember resource.")]
        [ValidatePattern('^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$', ErrorMessage = "RoleID must be the GUID of the Role.")]
        [string]$RoleID,
        [parameter(Mandatory = $true, ParameterSetName = "InvoiceDownload")]
        [parameter(Mandatory = $true, ParameterSetName = "InvoiceLineItems")]
        [ValidateScript({ $Resource -eq 'InvoiceDownload' -or $Resource -eq 'InvoiceLineItems' }, ErrorMessage = "InvoiceID parameters it's only available on InvoiceDownload resource.")]
        [string]$InvoiceID,
        [parameter(ParameterSetName = "Predefined")]
        [parameter(Mandatory = $true, ParameterSetName = "InvoiceDownload")]
        [ValidateScript({ $Resource -eq 'InvoiceDownload' }, ErrorMessage = "DownloadPath parameters it's only available on InvoiceDownload resource.")]
        [string]$DownloadPath,
        [parameter(Mandatory = $true, ParameterSetName = "InvoiceLineItems")]
        [ValidateScript({ $Resource -eq 'InvoiceLineItems' }, ErrorMessage = "InlineType parameters it's only available on InvoiceLineItems resource.")]
        [ValidateSet(
            "Recurring",
            "OneTime", IgnoreCase = $true)]
        [string]$InlineType
        
    )
    begin {
        $ErrorActionPreference = "Stop"
        if ($Resource -eq 'Subscriptions' -and !$CustomerID) {
            Write-Error "Customer Tenant Id must be send by parameter CustomerID. Please validate and try again."
            break
        }
        $ErrorActionPreference = "SilentlyContinue"
    }
    process {
        $BaseURL = "https://api.partnercenter.microsoft.com/v1"

        if ($CustomURL) {
            $ResourceURL = $CustomURL
        }
        else {
            switch ($Resource) {
                Customers { $ResourceURL = "/customers" }
                PartnerProfile { $ResourceURL = "/profiles/mpn" }
                SupportProfile { $ResourceURL = "/profiles/support" }
                Organization { $ResourceURL = '/profiles/organization' }
                ResellerRequestLink { $ResourceURL = '/customers/relationshiprequests' }
                Subscriptions { $ResourceURL = "/customers/$CustomerID/subscriptions" }
                Roles { $ResourceURL = "/roles" }
                RoleMember { $ResourceURL = "/roles/$RoleID/usermembers" }
                Invoices { $ResourceURL = "/invoices" }
                InvoiceDownload { $ResourceURL = "/invoices/$InvoiceID/documents/statement" }
                InvoiceLineItems { 
                    if ($InlineType -eq "Recurring") {
                        $ResourceURL = "/invoices/$InvoiceID/lineitems?provider=office&invoicelineitemtype=billinglineitems&size=2000"
                    }
                    else {
                        $ResourceURL = "/invoices/$InvoiceID/lineitems?provider=onetime&invoicelineitemtype=billinglineitems&size=2000"
                    }
                }
                Default { $ResourceURL = "/profiles/mpn" }
            }
        }

        $FinalURL = ($BaseURL + $ResourceURL)

        $AccessToken = Get-Variable -Name "RevoPartnerBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $AccessToken) {
            $Headers = @{}
            $Headers.Add("Authorization", $AccessToken)
            $Headers.Add("Accept", "application/json")
            $Headers.Add("X-Locale", "es-PE")
    
            if ($Resource -eq 'InvoiceDownload') {
                $WebRequest = Invoke-WebRequest -Method Get -Uri $FinalURL -Headers $Headers -ErrorVariable InvokeError -OutFile (Join-Path $DownloadPath "$InvoiceID.pdf")
            }
            else {
                $WebRequest = Invoke-WebRequest -Method Get -Uri $FinalURL -Headers $Headers -ErrorVariable InvokeError
            }

            if ($InvokeError.Count -gt 0) {
                if ($InvokeError.ErrorRecord.ToString() -like "This resource can't be accessed by application credentials.") {
                    $ModuleError = "This resource can't be accessed by application credentials. Try something diferent or use another credentials."
                }
                elseif ($InvokeError.ErrorRecord.ErrorDetails) {
                    switch (($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).code) {
                        20002 { $ModuleError = ($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).description }
                        403 { $ModuleError = ($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).description }
                        default { $ModuleError = "Undetermined error. Please try with other resource." }
                    }
                }
                else {
                    switch (($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).error.code) {
                        'ExpiredAuthenticationToken' {
                            $ModuleError = "Your bearer token was expired, please reconnect with New-RevoPartnerAccess"
                        }
                        'AuthenticationFailedInvalidHeader' {
                            $ModuleError = "Your bearer token was malformed, please reconnect with New-RevoPartnerAccess"
                        }
                        'AuthenticationFailed' {
                            $ModuleError = "Your bearer token was invalid, please reconnect with New-RevoPartnerAccess"
                        }
                        default {
                            $ModuleError = "Undetermined error. Please try with other resource or reconnect."
                        }
                    }
                }

            }
            else {
                if ($WebRequest) {
                    if ($WebRequest.Content[0] -ne '{') {
                        $Output = $WebRequest.Content.Substring(1) | ConvertFrom-Json -Depth 10
                    }
                    else {
                        $Output = $WebRequest.Content | ConvertFrom-Json -Depth 10
                    }
                }
                else {
                    if ($Resource -ne 'InvoiceDownload') {
                        $ModuleError = "Nothings returns. Try again."
                    }
                }
            }
        }
        else {
            $ModuleError = "Cannot get the bearer token, please first connect by New-RevoPartnerAccess"
        }
    }
    end {
        $ErrorActionPreference = "Continue"
        if ($ModuleError) {
            Write-Error $ModuleError
        }
        else {
            if ($Resource -eq 'InvoiceDownload') {
                Return (Join-Path $DownloadPath "$InvoiceID.pdf")
            }
            else{
                Return $Output
            }
        }
    }
}