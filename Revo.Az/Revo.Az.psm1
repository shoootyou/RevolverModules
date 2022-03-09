function New-RevoAzAccess{
    param(
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [parameter(Mandatory=$false, ParameterSetName = "UserAuthentication")]
        [string]$TenantID,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$ClientID,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [string]$CertificateThumbprint,
        [parameter(Mandatory=$false, ParameterSetName = "UserAuthentication")]
        [switch]$DeviceAuthentication,
        [parameter(Mandatory=$true, ParameterSetName = "ServicePrincipal")]
        [ValidateSet('CurrentUser','LocalMachine')]
        [String]$CertificateStore = 'CurrentUser',
        [parameter(Mandatory=$false, ParameterSetName = "ServicePrincipal")]
        [switch]$SecureOutput
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{

        if ($CertificateThumbprint) {
            if ($null -eq $env:windir -and $CertificateStore -eq 'LocalMachine') {
                Write-Warning 'On Linux systems you must use Currentuser as value of CertificateStore'
                $CertificateStore = 'CurrentUser'
            }
            
            $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::My 
            $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$CertificateStore
            $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation) 
            $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $Certificate = $Store.Certificates | Where-Object {$_.Thumbprint -eq $CertificateThumbprint}

            if ($null -eq $Certificate) {
                $ParseInformation = $null
                $ParseCertificate = $null
            }
            else {
                $Scope = "https://graph.microsoft.com/.default"
                $Resource = "https://management.core.windows.net/"
        
                # Create base64 hash of certificate
                $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())
        
                # Create JWT timestamp for expiration
                $StartDate = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
                $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(60)).TotalSeconds
                $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)
        
                # Create JWT validity start timestamp
                $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
                $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)
        
                # Create JWT header
                $JWTHeader = @{
                    alg = "RS256"
                    typ = "JWT"
                    # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
                    x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
                }
        
                # Create JWT payload
                $JWTPayLoad = @{
                    # What endpoint is allowed to use this JWT
                    aud = "https://login.microsoftonline.com/$TenantID/oauth2/token"
                    # Expiration timestamp
                    exp = $JWTExpiration
                    # Issuer = your application
                    iss = $ClientID
                    # JWT ID: random guid
                    jti = [guid]::NewGuid()
                    # Not to be used before
                    nbf = $NotBefore
                    # JWT Subject
                    sub = $ClientID
                }
        
                # Convert header and payload to base64
                $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
                $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)
        
                $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
                $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)
        
                # Join header and Payload with "." to create a valid (unsigned) JWT
                $JWT = $EncodedHeader + "." + $EncodedPayload
        
                # Get the private key object of your certificate
                $PrivateKey = $Certificate.PrivateKey
        
                # Define RSA signature and hashing algorithm
                $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
                $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
        
                # Create a signature of the JWT
                $Signature = [Convert]::ToBase64String(
                    $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
                ) -replace '\+','-' -replace '/','_' -replace '='
        
                # Join the signature to the JWT with "."
                $JWT = $JWT + "." + $Signature
        
                # Create a hash with body parameters
                $Body = @{
                    client_id = $ClientID
                    client_assertion = $JWT
                    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    scope = $Scope
                    grant_type = "client_credentials"
                    resource = $Resource
                }
        
                $Url = "https://login.microsoftonline.com/$TenantID/oauth2/token"
        
                # Use the self-generated JWT as Authorization
                $Header = @{
                    Authorization = "Bearer $JWT"
                }
        
                # Splat the parameters for Invoke-Restmethod for cleaner code
                $PostSplat = @{
                    ContentType = 'application/x-www-form-urlencoded'
                    Method = 'POST'
                    Body = $Body
                    Uri = $Url
                    Headers = $Header
                }
        
                $AccessToken = Invoke-RestMethod @PostSplat

                $ParseInformation = [pscustomobject]@{
                    'Token' = $AccessToken.access_token;
                    'ExpiresOn' = (Get-Date -UnixTimeSeconds $AccessToken.expires_on);
                    'Type' = $AccessToken.token_type;
                    'TenantId' = $TenantID;
                    'UserId' = $ClientID;
                }
            }

        }
        else{
            if ($DeviceAuthentication.IsPresent) {
                $Module = Get-Module -Name Az.Accounts -ListAvailable
                if($null -eq $Module){
                    Install-Module -Name Az.Accounts -Scope CurrentUser
                    Import-Module -Name Az.Accounts -Scope CurrentUser
                }
                else{
                    Import-Module -Name Az.Accounts -Scope CurrentUser
                }
                if($null -eq $TenantID){
                    Connect-AzAccount -UseDeviceAuthentication -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
                }
                else{
                    Connect-AzAccount -Tenant $TenantID -UseDeviceAuthentication -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
                }
                $AccessToken = Get-AzAccessToken

                $ParseInformation = [pscustomobject]@{
                    'Token' = $AccessToken.Token;
                    'ExpiresOn' = $AccessToken.ExpiresOn.LocalDateTime;
                    'Type' = $AccessToken.Type;
                    'TenantId' = $AccessToken.TenantId;
                    'UserId' = $AccessToken.UserId;
                }
            }
            else {
                $Module = Get-Module -Name Az.Accounts -ListAvailable
                if($null -eq $Module){
                    Install-Module -Name Az.Accounts -Scope CurrentUser
                    Import-Module -Name Az.Accounts -Scope Local
                }
                else{
                    Import-Module -Name Az.Accounts -Scope Local
                }

                if($null -eq $TenantID){
                    Connect-AzAccount -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
                }
                else{
                    Connect-AzAccount -Tenant $TenantID -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
                }
                $AccessToken = Get-AzAccessToken

                $ParseInformation = [pscustomobject]@{
                    'Token' = $AccessToken.Token;
                    'ExpiresOn' = $AccessToken.ExpiresOn.LocalDateTime;
                    'Type' = $AccessToken.Type;
                    'TenantId' = $AccessToken.TenantId;
                    'UserId' = $AccessToken.UserId;
                }
            }
        }
        
    }
    end{
        $ErrorActionPreference = "Continue"
        if ($null -eq $ParseInformation -and $null -eq $ParseCertificate) {
            Write-Error "Certificate not found on StoreLocation. Please install first."
        }
        elseif($null -eq $ParseInformation){
            Write-Error "Cannot get the bearer token with the supplied parameters. Please check the values."
        }
        else{
            New-Variable -Name "RevoAzBearerToken" -Value ($ParseInformation.Type + " " + $ParseInformation.Token) -Scope Global -Force -ErrorAction SilentlyContinue
            New-Variable -Name "RevoAzBearerTokenDetails" -Value $ParseInformation -Scope Global -Force -ErrorAction SilentlyContinue
            if(!$SecureOutput){
                Return $ParseInformation.Type + " " + $ParseInformation.Token
            }
        }
    }
}

function New-RevoAzMSALAccess{
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
                $ParseInformation = Get-MsalToken -ClientId $ClientID -TenantId $TenantID -ClientCertificate $Certificate -Scopes 'https://management.core.windows.net//.default'   
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
            New-Variable -Name "RevoAzBearerToken" -Value ($ParseInformation.TokenType + " " + $ParseInformation.AccessToken) -Scope Global -Force -ErrorAction SilentlyContinue
            New-Variable -Name "RevoAzBearerTokenDetails" -Value $ParseInformation -Scope Global -Force -ErrorAction SilentlyContinue
            if(!$SecureOutput){
                Return $ParseInformation.TokenType + " " + $ParseInformation.AccessToken
            }
        }
    }
}

function Get-RevoAzTenants{
    param(

    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/tenants?api-version=2020-01-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)
    
            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers -ErrorVariable InvokeError

            if ($InvokeError.Count -gt 0) {
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
            else {
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
                if($null -ne $WebResponse.nextLink){
                    do{
                        $AzTenants += $WebResponse.value
                        $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                        $WebResponse = $WebRequest.Content | ConvertFrom-Json
                    }
                    until($null -eq $WebResponse.nextLink)
                }
                else {
                    $AzTenants += $WebResponse.value
                }

                $Output = New-Object -TypeName System.Collections.ArrayList
                if($RevoAzBearerTokenDetails.UserId -like "*@*"){
                    foreach($Tenant in $AzTenants){
                        $ParseInformation = [pscustomobject]@{
                            'DisplayName' = $Tenant.displayName;
                            'DefaultDomain' = $Tenant.defaultDomain;
                            'TenantId' = $Tenant.tenantId;
                            'MicrosoftDomain' = ($Tenant.domains | Where-Object {$_ -like "*.onmicrosoft.com" -and $_ -notlike "*mail.onmicrosoft.com"});
                            'CustomDomains' = (($Tenant.domains | Where-Object {$_ -notlike "*.onmicrosoft.com"} ) -join ",");
                            'TenantCategory' = $Tenant.tenantCategory;
                            'Id' = $Tenant.id;
                        }
                        $Output.add($ParseInformation) | Out-Null
                        $ParseInformation = $null
                    }
                }
                else{
                    foreach($Tenant in $AzTenants){
                        $ParseInformation = [pscustomobject]@{
                            'TenantId' = $Tenant.tenantId;
                            'TenantCategory' = $Tenant.tenantCategory;
                            'Id' = $Tenant.id;
                        }
                        $Output.add($ParseInformation) | Out-Null
                        $ParseInformation = $null
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
        if($BearerTokenFailed){
            Write-Error "Your bearer token was invalid, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenInvalidHeader) {
            Write-Error "Your bearer token was malformed, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenExpired) {
            Write-Error "Your bearer token was expired, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzSubscriptions{
    param(

    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions?api-version=2020-01-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)
    
            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers -ErrorVariable InvokeError

            if ($InvokeError.Count -gt 0) {
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
            else{
                $WebResponse = $WebRequest.Content | ConvertFrom-Json

                if($null -ne $WebResponse.nextLink){
                    do{
                        $AzSubscriptions += $WebResponse.value
                        $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                        $WebResponse = $WebRequest.Content | ConvertFrom-Json
                    }
                    until($null -eq $WebResponse.nextLink)
                }
                else {
                    $AzSubscriptions += $WebResponse.value
                }
    
                $Output = New-Object -TypeName System.Collections.ArrayList
                foreach($Subscription in $AzSubscriptions){
                    if($null -eq $Subscription.managedByTenants.TenantId){
                        $IsManaged = $false;
                    }
                    else{
                        $IsManaged = $true;
                    }
                    $ParseInformation = [pscustomobject]@{
                        'AuthorizationSource' = $Subscription.authorizationSource;
                        'SubscriptionId' = $Subscription.subscriptionId;
                        'TenantId' = $Subscription.tenantId;
                        'DisplayName' = $Subscription.displayName;
                        'State' = $Subscription.state;
                        'LocationPlacementId' = $Subscription.subscriptionPolicies.locationPlacementId;
                        'QuotaId' = $Subscription.subscriptionPolicies.quotaId;
                        'SpendingLimit' = $Subscription.subscriptionPolicies.spendingLimit;
                        'Id' = $Subscription.id;
                        'IsManaged' = $IsManaged;
                    }
                    $Output.add($ParseInformation) | Out-Null
                    $ParseInformation = $null
                }
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenFailed){
            Write-Error "Your bearer token was invalid, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenInvalidHeader) {
            Write-Error "Your bearer token was malformed, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenExpired) {
            Write-Error "Your bearer token was expired, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzLocations{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/locations?api-version=2020-01-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)
    
            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers -ErrorVariable InvokeError

            if ($InvokeError.Count -gt 0) {
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
            else{
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
                if($null -ne $WebResponse.nextLink){
                    do{
                        $AzLocations += $WebResponse.value
                        $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                        $WebResponse = $WebRequest.Content | ConvertFrom-Json
                    }
                    until($null -eq $WebResponse.nextLink)
                }
                else {
                    $AzLocations += $WebResponse.value
                }

                $Output = New-Object -TypeName System.Collections.ArrayList
                foreach($Location in $AzLocations){
                    $ParseInformation = [pscustomobject]@{
                        'Name' = $Location.name;
                        'DisplayName' = $Location.displayName;
                        'RegionalDisplayName' = $Location.regionalDisplayName;
                        'RegionType' = $Location.metadata.regionType;
                        'RegionCategory' = $Location.metadata.regionCategory;
                        'GeographyGroup' = $Location.metadata.geographyGroup;
                        'Longitude' = $Location.metadata.longitude;
                        'Latitude' = $Location.metadata.latitude;
                        'PhysicalLocation' = $Location.metadata.physicalLocation;
                        'PairedRegionName' = ($Location.metadata.pairedRegion.name -Join ",");
                        'PairedRegionId' = ($Location.metadata.pairedRegion.Id -Join ",");
                    } 
                    $Output.add($ParseInformation) | Out-Null
                    $ParseInformation = $null
                }
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenFailed){
            Write-Error "Your bearer token was invalid, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenInvalidHeader) {
            Write-Error "Your bearer token was malformed, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenExpired) {
            Write-Error "Your bearer token was expired, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzResourceGroups{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/resourcegroups?api-version=2020-10-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)
    
            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers -ErrorVariable InvokeError
            if ($InvokeError.Count -gt 0) {
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
            else{
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
                if($null -ne $WebResponse.nextLink){
                    do{
                        $AzResourceGroups += $WebResponse.value
                        $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                        $WebResponse = $WebRequest.Content | ConvertFrom-Json
                    }
                    until($null -eq $WebResponse.nextLink)
                }
                else {
                    $AzResourceGroups += $WebResponse.value
                }

                $Output = New-Object -TypeName System.Collections.ArrayList
                foreach($ResourceGroup in $AzResourceGroups){
                    
                    if($null -eq $ResourceGroup.tags){
                        $IsTagged = 'Untagged'
                    }
                    else{
                        $IsTagged = 'Tagged'
                    }

                    $ParseInformation = [pscustomobject]@{
                        'Name' = $ResourceGroup.name;
                        'Location' = $ResourceGroup.location;
                        'IsTagged' = $IsTagged;
                        'Tags' = ($ResourceGroup.tags | Measure-Object).Count;
                        'Type' = $ResourceGroup.type;
                        'Id' = $ResourceGroup.id;
                        'SubscriptionId' = (($ResourceGroup.id -split "/")[2]);
                    }
                    $Output.add($ParseInformation) | Out-Null
                    $ParseInformation = $null
                }
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenFailed){
            Write-Error "Your bearer token was invalid, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenInvalidHeader) {
            Write-Error "Your bearer token was malformed, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif ($BearerTokenExpired) {
            Write-Error "Your bearer token was expired, please reconnect with New-RevoAzBearerByCertificate"
        }
        elseif($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzResources{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/resources?" + '$expand' + "=createdTime,provisioningState,changedTime&api-version=2020-10-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)

            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers
            $WebResponse = $WebRequest.Content | ConvertFrom-Json
            do{
                $AzResources += $WebResponse.value
                $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
            }
            until($null -eq $WebResponse.nextLink)

            $Output = New-Object -TypeName System.Collections.ArrayList
            foreach($Resource in $AzResources){

                if($null -eq $Resource.tags){
                    $IsTagged = $false
                }
                else{
                    $IsTagged = $true
                }

                $ParseInformation = [pscustomobject]@{
                    'Name' = $Resource.name;
                    'Type' = $Resource.type;
                    'ResourceGroup' = (($Resource.id -split "/")[4]);
                    'Location' = $Resource.location;
                    'SubscriptionId' = (($Resource.id -split "/")[2]);
                    'SKUName' = $Resource.sku.name
                    'PlanName' = $Resource.plan.name
                    'Kind' = $Resource.kind;
                    'ManagedBy' = $Resource.managedBy;
                    'Identity' = ([string]$Resource.identity -replace "@{" -replace "}");
                    'PlanProduct' = $Resource.plan.product
                    'PlanPromotionCode' = $Resource.plan.promotionCode
                    'PlanPublisher' = $Resource.plan.publisher
                    'PlanVersion' = $Resource.plan.version
                    'ProvisioningState' = $Resource.provisioningState;
                    'SKUCapacity' = $Resource.sku.capacity
                    'SKUFamily' = $Resource.sku.family
                    'SKUModel' = $Resource.sku.model
                    'SKUSize' = $Resource.sku.size
                    'SKUTier' = $Resource.sku.tier
                    'Zones' = ($Resource.Zones -join ",");
                    'Tags' = ([string]$Resource.tags -replace "@{" -replace "}");
                    'IsTagged' = $IsTagged;
                    'SystemData' = ([string]$Resource.SystemData -replace "@{" -replace "}");
                    'Id' = $Resource.id;
                }
                $Output.add($ParseInformation) | Out-Null
                $ParseInformation = $null
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzVm{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
        $TextInfo = (Get-Culture).TextInfo
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/providers/Microsoft.Compute/virtualMachines?api-version=2020-12-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)

            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers
            $WebResponse = $WebRequest.Content | ConvertFrom-Json
            do{
                $AzVms += $WebResponse.value
                $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
            }
            until($null -eq $WebResponse.nextLink)

            $Output = New-Object -TypeName System.Collections.ArrayList
            foreach($Vm in $AzVms){
                
                $ResourceURL = $AzureManagement + "$($VM.id)/instanceView?api-version=2020-12-01"

                $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
                $Headers = @{}
                $Headers.Add("Authorization",$AccessToken)
    
                $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers
                $WebResponse = $WebRequest.Content | ConvertFrom-Json

                if($null -eq $Vm.tags){
                    $IsTagged = $false
                }
                else{
                    $IsTagged = $true
                }
                if($null -ne $Vm.properties.osProfile.windowsConfiguration){
                    $OperatingSystem = "Windows"
                    $ProvisionVMAgent = $Vm.properties.osProfile.windowsConfiguration.provisionVMAgent;
                    $PatchMode = $VM.properties.osProfile.windowsConfiguration.patchSettings.patchMode;
                    $EnableAutomaticUpdates = $VM.properties.osProfile.windowsConfiguration.enableAutomaticUpdates;
                    $DisablePasswordAuthentication = $false;
                    $PublicKeysLocation =$null;
                }
                else{
                    $OperatingSystem = "Linux"
                    $ProvisionVMAgent = $Vm.properties.osProfile.linuxconfiguration.provisionVMAgent;
                    $PatchMode = $VM.properties.osProfile.linuxconfiguration.patchSettings.patchMode;
                    $EnableAutomaticUpdates = $null;
                    $DisablePasswordAuthentication = $VM.properties.osProfile.linuxconfiguration.disablePasswordAuthentication;
                    $PublicKeysLocation =$VM.properties.osProfile.linuxconfiguration.ssh.publicKeys.path;
                }
                if($null -ne $Vm.properties.storageProfile.osDisk.vhd.uri){
                    $DiskOSNeedMigrateDisk = $true;
                }
                else{
                    $DiskOSNeedMigrateDisk = $false;
                }
                if($null -ne $VM.properties.diagnosticsProfile.bootDiagnostics.storageUri){
                    $BootDiagnosticsNeedMigrate = $true;
                }
                else{
                    $BootDiagnosticsNeedMigrate = $false;
                }

                $ParseInformation = [pscustomobject]@{
                    'Name' = $Vm.name;
                    'ResourceGroup' = ($VM.id -split "/")[4];
                    'SubscriptionId' = (($Resource.id -split "/")[2]);
                    'Location' = $Vm.location;
                    'LastStatus' = $TextInfo.ToTitleCase($WebResponse.statuses[1].code -replace 'PowerState/');
                    'LastStatusTime' = $WebResponse.statuses[0].time;
                    'ComputerName' = $Vm.properties.osProfile.computerName;
                    'VmSize' = $Vm.properties.hardwareProfile.vmSize;
                    'OperatingSystem' = $OperatingSystem;
                    'Zones' = ($Vm.Zones -join ",");
                    'AdminUsername' = $Vm.properties.osProfile.adminUsername;
                    'VmId' = $Vm.properties.vmId;
                    'ImagePublisher' = $Vm.properties.storageProfile.imageReference.publisher;
                    'ImageOffer' = $Vm.properties.storageProfile.imageReference.offer;
                    'ImageSKU' = $Vm.properties.storageProfile.imageReference.sku;
                    'ImageVersion' = $Vm.properties.storageProfile.imageReference.version;
                    'ImageExactVersion' = $Vm.properties.storageProfile.imageReference.exactVersion;
                    'DiskOSName' = $Vm.properties.storageProfile.osDisk.name;
                    'DiskOSSizeGB' = $Vm.properties.storageProfile.osDisk.diskSizeGB;
                    'DiskOSCreateOption' = $Vm.properties.storageProfile.osDisk.createOption;
                    'DiskOSCaching' = $Vm.properties.storageProfile.osDisk.caching;
                    'DiskOSWriteAcceleratorEnabled' = $Vm.properties.storageProfile.osDisk.writeAcceleratorEnabled;
                    'DiskOSId' = $Vm.properties.storageProfile.osDisk.managedDisk.id;
                    'DiskOSNeedMigrateDisk' = $DiskOSNeedMigrateDisk;
                    'DiskDataCount' = $VM.properties.storageProfile.dataDisks.Count;
                    'DiskDataNames' = ($VM.properties.storageProfile.dataDisks.name -join ",");
                    'DiskDataIds' = ($VM.properties.storageProfile.dataDisks.managedDisk.id -join ",");
                    'ProvisionVMAgent' = $ProvisionVMAgent;
                    'PatchMode' = $PatchMode;
                    'EnableAutomaticUpdates' = $EnableAutomaticUpdates;
                    'DisablePasswordAuthentication' = $DisablePasswordAuthentication;
                    'PublicKeysLocation' = $PublicKeysLocation;
                    'NetworkInterfaces' = $VM.properties.networkProfile.networkInterfaces.Count;
                    'NetworkInterfacesId' = $VM.properties.networkProfile.networkInterfaces.Id -join ",";
                    'BootDiagnostics' = $VM.properties.diagnosticsProfile.bootDiagnostics.enabled;
                    'BootDiagnosticsStorage' = $VM.properties.diagnosticsProfile.bootDiagnostics.storageUri;
                    'BootDiagnosticsNeedMigrate' = $BootDiagnosticsNeedMigrate;
                    'ProvisioningState' = $Vm.properties.provisioningState;
                    'Extensions' = ($VM.resources -replace ("@{id=" + $VM.id + "/extensions/") -replace "}" -join ",");
                    'ExtensionsNumber' = $Vm.resources.Count;
                    'Tags' = ([string]$Vm.tags -replace "@{" -replace "}");
                    'IsTagged' = $IsTagged;
                    'Type' = $Vm.type;
                    'Id' = $Vm.id;
                }
                $Output.add($ParseInformation) | Out-Null
                $ParseInformation = $null
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzAdvisor{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId,
        [parameter(Mandatory=$false, ParameterSetName = "MoreDetails")]
        [switch]$MoreDetails,
        [parameter(Mandatory=$false, ParameterSetName = "MoreDetails")]
        [ValidateSet("Daily","Weekly","Monthly", IgnoreCase = $true)]
        [string]$AggregationLevel
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/AdvisorScore?api-version=2020-07-01-preview"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)

            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers
            $WebResponse = $WebRequest.Content | ConvertFrom-Json
            do{
                $AzAdvisor += $WebResponse.value
                $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
            }
            until($null -eq $WebResponse.nextLink)

            $Output = New-Object -TypeName System.Collections.ArrayList
            if($MoreDetails.IsPresent){
                foreach($Advisor in $AzAdvisor){

                    foreach($TimeSeries in $Advisor.properties.timeSeries){
                        $AggregationLevelCount = 0
                        do{
                            foreach ($ScoreHistory in $TimeSeries[$AggregationLevelCount].scoreHistory) {
                                if($AggregationLevel -eq "Daily"){
                                    if($TimeSeries[$AggregationLevelCount].aggregationLevel -eq "Daily"){
                                        $ParseInformation = [pscustomobject]@{
                                            'Name' = $Advisor.name;
                                            'Date' = $ScoreHistory.date;
                                            'Score' = $ScoreHistory.score;
                                            'ConsumptionUnits' = $ScoreHistory.consumptionUnits;
                                            'ImpactedResourceCount' = $ScoreHistory.impactedResourceCount;
                                            'PotentialScoreIncrease' = $ScoreHistory.potentialScoreIncrease;
                                            'AggregationLevel' = $TimeSeries[$AggregationLevelCount].aggregationLevel;
                                            'SubscriptionId' = (($Resource.id -split "/")[2]);
                                        }
                                        $Output.add($ParseInformation) | Out-Null
                                        $ParseInformation = $null
                                    }
                                }
                                elseif($AggregationLevel -eq "Weekly"){
                                    if($TimeSeries[$AggregationLevelCount].aggregationLevel -eq "Weekly"){
                                        $ParseInformation = [pscustomobject]@{
                                            'Name' = $Advisor.name;
                                            'Date' = $ScoreHistory.date;
                                            'Score' = $ScoreHistory.score;
                                            'ConsumptionUnits' = $ScoreHistory.consumptionUnits;
                                            'ImpactedResourceCount' = $ScoreHistory.impactedResourceCount;
                                            'PotentialScoreIncrease' = $ScoreHistory.potentialScoreIncrease;
                                            'AggregationLevel' = $TimeSeries[$AggregationLevelCount].aggregationLevel;
                                            'SubscriptionId' = (($Resource.id -split "/")[2]);
                                        }
                                        $Output.add($ParseInformation) | Out-Null
                                        $ParseInformation = $null
                                    }
                                }
                                elseif($AggregationLevel -eq "Monthly"){
                                    if($TimeSeries[$AggregationLevelCount].aggregationLevel -eq "Monthly"){
                                        $ParseInformation = [pscustomobject]@{
                                            'Name' = $Advisor.name;
                                            'Date' = $ScoreHistory.date;
                                            'Score' = $ScoreHistory.score;
                                            'ConsumptionUnits' = $ScoreHistory.consumptionUnits;
                                            'ImpactedResourceCount' = $ScoreHistory.impactedResourceCount;
                                            'PotentialScoreIncrease' = $ScoreHistory.potentialScoreIncrease;
                                            'AggregationLevel' = $TimeSeries[$AggregationLevelCount].aggregationLevel;
                                            'SubscriptionId' = (($Resource.id -split "/")[2]);
                                        }
                                        $Output.add($ParseInformation) | Out-Null
                                        $ParseInformation = $null
                                    }
                                }
                                else{
                                    $ParseInformation = [pscustomobject]@{
                                        'Name' = $Advisor.name;
                                        'Date' = $ScoreHistory.date;
                                        'Score' = $ScoreHistory.score;
                                        'ConsumptionUnits' = $ScoreHistory.consumptionUnits;
                                        'ImpactedResourceCount' = $ScoreHistory.impactedResourceCount;
                                        'PotentialScoreIncrease' = $ScoreHistory.potentialScoreIncrease;
                                        'AggregationLevel' = $TimeSeries[$AggregationLevelCount].aggregationLevel;
                                        'SubscriptionId' = (($Resource.id -split "/")[2]);
                                    }
                                    $Output.add($ParseInformation) | Out-Null
                                    $ParseInformation = $null
                                }
                            }
                            $AggregationLevelCount++
                        }
                        until($AggregationLevelCount -eq $TimeSeries.AggregationLevel.Length)
                    }
                }
            }
            else{
                foreach($Advisor in $AzAdvisor){
                    if($Advisor.name -notlike "*-*"){
                        $ParseInformation = [pscustomobject]@{
                            'Name' = $Advisor.name;
                            'Date' = $Advisor.properties.lastRefreshedScore.date;
                            'Score' = $Advisor.properties.lastRefreshedScore.score;
                            'ConsumptionUnits' = $Advisor.properties.lastRefreshedScore.consumptionUnits;
                            'ImpactedResourceCount' = $Advisor.properties.lastRefreshedScore.impactedResourceCount;
                            'PotentialScoreIncrease' = $Advisor.properties.lastRefreshedScore.potentialScoreIncrease;
                            'Type' = $Advisor.type;
                            'Id' = $Advisor.id;
                        }
                    }
                    $Output.add($ParseInformation) | Out-Null
                    $ParseInformation = $null
                }
            }

        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzSecureScore{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores?api-version=2020-01-01"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)

            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers
            $WebResponse = $WebRequest.Content | ConvertFrom-Json
            do{
                $AzSecureScore += $WebResponse.value
                $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
            }
            until($null -eq $WebResponse.nextLink)
            if($SubscriptionId.GetType().BaseType.Name -eq "Array"){
                return "sdsdsd"
            }

            $Output = New-Object -TypeName System.Collections.ArrayList
            foreach($SecureScore in $AzSecureScore){
                $ParseInformation = [pscustomobject]@{
                    'DisplayName' = $SecureScore.properties.displayName;
                    'Name' = $SecureScore.name;
                    'SubscriptionId' = (($Resource.id -split "/")[2]);
                    'ScoreMax' = $SecureScore.properties.score.max;
                    'ScoreCurrent' = $SecureScore.properties.score.current;
                    'ScorePercentageNumber' = $SecureScore.properties.score.percentage;
                    'ScorePercentage' = $SecureScore.properties.score.percentage.ToString("P");
                    'Weight' = $SecureScore.properties.weight;
                }
                $Output.add($ParseInformation) | Out-Null
                $ParseInformation = $null
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function Get-RevoAzSecureScoreControls{
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNull()]
        [string]$SubscriptionId,
        [parameter(Mandatory=$false)]
        [switch]$MoreDetails
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        $AzureManagement = "https://management.azure.com"
        $ResourceURL = $AzureManagement + "/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls?api-version=2020-01-01&" + '$expand' + "=definition"

        $AccessToken = Get-Variable -Name "RevoAzBearerToken" -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $AccessToken){
            $Headers = @{}
            $Headers.Add("Authorization",$AccessToken)

            $WebRequest = Invoke-WebRequest -Method Get -Uri $ResourceURL -Headers $Headers
            $WebResponse = $WebRequest.Content | ConvertFrom-Json
            do{
                $AzSecureScoreControls += $WebResponse.value
                $WebRequest = Invoke-WebRequest -Method Get -Uri $WebResponse.nextLink -Headers $Headers
                $WebResponse = $WebRequest.Content | ConvertFrom-Json
            }
            until($null -eq $WebResponse.nextLink)

            $Output = New-Object -TypeName System.Collections.ArrayList
            if($MoreDetails.IsPresent){
                foreach($SecureScoreControls in $AzSecureScoreControls){
                    foreach ($AssessmentDefinitions in $secureScoreControls.properties.definition.properties.assessmentDefinitions) {
                        $ParseInformation = [pscustomobject]@{
                            'DisplayName' = $SecureScoreControls.properties.displayName;
                            'HealthyResourceCount' = $SecureScoreControls.properties.healthyResourceCount;
                            'UnhealthyResourceCount' = $SecureScoreControls.properties.unhealthyResourceCount;
                            'NotApplicableResourceCount' = $SecureScoreControls.properties.notApplicableResourceCount;
                            'ScoreCurrent' = $SecureScoreControls.properties.score.current;
                            'ScoreMax' = $SecureScoreControls.properties.score.max;
                            'ScorePercentage' = $SecureScoreControls.properties.score.percentage;
                            'Weight' = $SecureScoreControls.properties.weight;
                            'DefinitionId' = $SecureScoreControls.properties.definition.id;
                            'DefinitionName' = $SecureScoreControls.properties.definition.name;
                            'DefinitionType' = $SecureScoreControls.properties.definition.type;
                            'DefinitionSourceType' = $SecureScoreControls.properties.definition.properties.source.sourceType;
                            'DefinitionDisplayName' = $SecureScoreControls.properties.definition.properties.displayName;
                            'DefinitionMaxScore' = $SecureScoreControls.properties.definition.properties.maxScore;
                            'AssessmentDefinitionsId' = $AssessmentDefinitions.id;
                            'AssessmentDefinitionsName' = $AssessmentDefinitions.Id.Substring($AssessmentDefinitions.Id.LastIndexOf("/")+1)
                            'Name' = $SecureScoreControls.name;
                            'Type' = $SecureScoreControls.type;
                            'Id' = $SecureScoreControls.id;
                            'SubscriptionId' = (($Resource.id -split "/")[2]);
                        }
                        $Output.add($ParseInformation) | Out-Null
                        $ParseInformation = $null
                    }
                }
            }
            else{
                foreach($SecureScoreControls in $AzSecureScoreControls){
                    $ParseInformation = [pscustomobject]@{
                        'DisplayName' = $SecureScoreControls.properties.displayName;
                        'HealthyResourceCount' = $SecureScoreControls.properties.healthyResourceCount;
                        'UnhealthyResourceCount' = $SecureScoreControls.properties.unhealthyResourceCount;
                        'NotApplicableResourceCount' = $SecureScoreControls.properties.notApplicableResourceCount;
                        'ScoreCurrent' = $SecureScoreControls.properties.score.current;
                        'ScoreMax' = $SecureScoreControls.properties.score.max;
                        'ScorePercentage' = $SecureScoreControls.properties.score.percentage;
                        'Weight' = $SecureScoreControls.properties.weight;
                        'Name' = $SecureScoreControls.name;
                        'Type' = $SecureScoreControls.type;
                        'Id' = $SecureScoreControls.id;
                        'SubscriptionId' = (($Resource.id -split "/")[2]);
                    }
                    $Output.add($ParseInformation) | Out-Null
                    $ParseInformation = $null
                }
            }
        }
        else {
            $BearerTokenError = $true
        }
    }
    end{
        $ErrorActionPreference = "Continue"
        if($BearerTokenError){
            Write-Error "Cannot get the bearer token, please first connect by New-RevoAzBearerByCertificate"
        }
        else{
            Return $Output
        }
    }
}

function New-RevoAzTable{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$StorageName,
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$TableName,
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Signature
    )
    begin{
        $ErrorActionPreference = "SilentlyContinue"
    }
    process{
        
        $UrlBase = "https://$StorageName.table.core.windows.net/Tables"
        $url = $UrlBase + $Signature
        
        $Headers = @{
            Accept = "application/json;odata=nometadata"
            "Content-Type" = "application/json"
        }
        
        $Body = New-Object PSObject
        $Body | Add-Member -type NoteProperty -Name 'TableName' -Value $TableName.Trim()
        $Body = $Body | ConvertTo-Json
        
        $WebRequest = Invoke-WebRequest -Method Post -Uri $url -Headers $Headers -Body $Body
        $LastError = $Error[0]
    }
    end{
        $ErrorActionPreference = "Continue"
        if($null -ne $WebRequest){
            Return $WebRequest.StatusDescription
        }
        else{
            Write-Error ($LastError.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.code
        }
    }
}