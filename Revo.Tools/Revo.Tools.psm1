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
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        $hashString = [System.BitConverter]::ToString($hash)
    }
    end{
        return $hashString.Replace('-', '')
    }
}

function Get-RevoFreshResources {
    param(
        [parameter(Mandatory = $true, ParameterSetName = "Predefined")]
        [parameter(Mandatory = $true, ParameterSetName = "Tickets")]
        [parameter(Mandatory = $true, ParameterSetName = "Custom")]
        [string]$OrganizationName,
        [parameter(Mandatory = $true, ParameterSetName = "Predefined")]
        [parameter(Mandatory = $true, ParameterSetName = "Tickets")]
        [parameter(Mandatory = $true, ParameterSetName = "Custom")]
        [securestring]$APIKey,
        [parameter(Mandatory = $true, ParameterSetName = "Custom")]
        [string]$CustomURL,
        [parameter(Mandatory = $true, ParameterSetName = "Predefined")]
        [parameter(Mandatory = $true, ParameterSetName = "Tickets")]
        [ValidateSet(
            "Agents",
            "Groups",
            "Requesters",
            "RequesterGroups",
            "Departments",
            "Tickets", IgnoreCase = $true)]
        [string]$Resource,
        [parameter(Mandatory = $true, ParameterSetName = "Tickets")]
        [ValidateScript({ $Resource -eq 'Tickets' }, ErrorMessage = "Since parameters it's only available on Tickets resource.")]
        [ValidateSet(
            "VeryFirstTime",
            "LastDay",
            "LastWeek",
            "LastMonth",
            "LasyYear", 
            "CurrentYear", IgnoreCase = $true)]
        [string]$Since
        
    )
    begin {
        $ErrorActionPreference = 'SilentlyContinue'
    }
    process {
        $BaseURL = "https://$OrganizationName.freshservice.com/api/v2"

        if ($CustomURL) {
            $ResourceURL = $CustomURL
        }
        else {
            switch ($Resource) {
                Agents { $ResourceURL = "/agents?per_page=100" }
                Groups { $ResourceURL = "/groups?per_page=100" }
                Requesters { $ResourceURL = "/requesters?per_page=100" }
                RequesterGroups { $ResourceURL = "/requester_groups?per_page=100" }
                Departments { $ResourceURL = "/departments?per_page=100" }
                Tickets { 
                    switch ($Since) {
                        VeryFirstTime { $ResourceURL = "/tickets?per_page=100&include=stats&updated_since=1900-01-19" }
                        LastDay { $ResourceURL = "/tickets?per_page=100&include=stats&updated_since=" + (Get-Date).AddDays(-1).ToString('yyyy-MM-dd') }
                        LastWeek { $ResourceURL = "/tickets?per_page=100&include=stats&updated_since=" + (Get-Date).AddDays(-7).ToString('yyyy-MM-dd') }
                        LastMonth { $ResourceURL = "/tickets?per_page=100&include=stats&updated_since=" + (Get-Date).AddDays(-30).ToString('yyyy-MM-dd') }
                        LasyYear { $ResourceURL = "/tickets?per_page=100&include=stats&updated_since=" + (Get-Date).AddDays(-360).ToString('yyyy-MM-dd') }
                        CurrentYear { $ResourceURL = "/tickets?per_page=100&include=stats&updated_since=" + ((Get-Date).Year.ToString() +'-01-01') }
                        Default { }
                    }
                }
                Default { }
            }
        }

        $FinalURL = ($BaseURL + $ResourceURL)

        $Password = ConvertTo-SecureString 'X' -AsPlainText -Force
        $Username = ConvertFrom-SecureString $APIKey -AsPlainText
        $Credentials = New-Object System.Management.Automation.PSCredential ($Username, $Password)
        
        $WebRequest = Invoke-WebRequest -Method GET -Uri $FinalURL -Authentication Basic -Credential $Credentials -ErrorVariable InvokeError
        if($null -ne $WebRequest){
            [System.Collections.ArrayList]$Output = @()
            $ResponseRes = (($WebRequest.Content | ConvertFrom-Json -Depth 100) | Get-Member | Where-Object {$_.MemberType -eq 'NoteProperty'}).Name
            ($WebRequest.Content | ConvertFrom-Json -Depth 100).$ResponseRes | ForEach-Object { $Output.Add($_) | Out-Null }
            if ($null -ne $WebRequest.Headers.Link) {
                do {
                    if([int]($WebRequest.Headers.'X-Ratelimit-Remaining'[0]) -lt 10){
                        Write-Warning "============ Throttling your request, please wait! ============"
                        Start-Sleep -Seconds 90
                    }
                    $WebRequest = Invoke-WebRequest -Method GET -Uri (($WebRequest.Headers.Link -split ";")[0].Replace("<", "").Replace(">", "")) -Authentication Basic -Credential $Credentials -ErrorVariable InvokeError
                    ($WebRequest.Content | ConvertFrom-Json -Depth 100).$ResponseRes | ForEach-Object { $Output.Add($_) | Out-Null }
                } until ($null -eq $WebRequest.Headers.Link)
            }
        }

        if ($InvokeError.Count -gt 0) {
            if ($InvokeError.ErrorRecord.ErrorDetails) {
                switch (($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 100).code) {
                    access_denied { $ModuleError = ($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 100).Message }
                    default { $ModuleError = "Undetermined error. Please try with other resource." }
                }
            }
        }

    }
    end {
        $ErrorActionPreference = "Continue"
        if ($ModuleError) {
            Write-Error $ModuleError
        }
        else {
            Return $Output
        }
    }
}

function Get-RevoPMResources {
    param(
        [parameter(Mandatory = $true, ParameterSetName = "Predefined")]
        [parameter(Mandatory = $true, ParameterSetName = "Custom")]
        [securestring]$APIKey,
        [parameter(Mandatory = $true, ParameterSetName = "Custom")]
        [string]$CustomURL,
        [parameter(Mandatory = $true, ParameterSetName = "Predefined")]
        [ValidateSet(
            "Projects",
            "Resources",
            "Timesheets", IgnoreCase = $true)]
        [string]$Resource,
        [ValidateScript({ $Resource -eq 'Timesheets' }, ErrorMessage = "ResourceID parameters it's only available on Timesheets resource. ")]
        [string]$ResourceID,
        [ValidateScript({ $Resource -eq 'Timesheets' }, ErrorMessage = "ProjectID parameters it's only available on Timesheets resource. ")]
        [string]$ProjectID
    )
    begin {
        $ErrorActionPreference = 'SilentlyContinue'
    }
    process {
        $BaseURL = "https://secure.projectmanager.com/api/v1"

        if ($CustomURL) {
            $ResourceURL = $CustomURL
        }
        else {
            switch ($Resource) {
                Projects { $ResourceURL = "/projects.json" }
                Resources { $ResourceURL = "/resources.json" }
                Timesheets {
                    if ($null -ne $ResourceID) {
                        $ResourceURL = "/resources/$ResourceID/timesheets.json"
                    }
                    elseif ($null -ne $ProjectID) {
                        $ResourceURL = "/projects/$ProjectID/timesheets.json"
                    }
                }
                Default { }
            }
        }

        $FinalURL = ($BaseURL + $ResourceURL)
        $APIHeader = ConvertFrom-SecureString $APIKey -AsPlainText
        $WebHeaders = @{}
        $WebHeaders.Add("apiKey","$APIHeader")

        $WebRequest = Invoke-WebRequest -Method GET -Uri $FinalURL -Headers $WebHeaders -Authentication None -ErrorVariable InvokeError
        if($null -ne $WebRequest){
            [System.Collections.ArrayList]$Output = @()
            $ResponseRes = (($WebRequest.Content | ConvertFrom-Json -Depth 100) | Get-Member | Where-Object {$_.MemberType -eq 'NoteProperty' -and $_.Name -ne 'status'}).Name
            ($WebRequest.Content | ConvertFrom-Json -Depth 100).$ResponseRes | ForEach-Object { $Output.Add($_) | Out-Null }
        }

        if ($InvokeError.Count -gt 0) {
            if ($InvokeError.InnerException.Message -like '*409*') {
                do {
                    Write-Warning " Retrying...."
                    Remove-Variable InvokeError -Force
                    Start-Sleep -Seconds 10
                    $WebRequest = Invoke-WebRequest -Method GET -Uri $FinalURL -Headers $WebHeaders -Authentication None -ErrorVariable InvokeError
                    if($null -ne $WebRequest){
                        [System.Collections.ArrayList]$Output = @()
                        $ResponseRes = (($WebRequest.Content | ConvertFrom-Json -Depth 100) | Get-Member | Where-Object {$_.MemberType -eq 'NoteProperty' -and $_.Name -ne 'status'}).Name
                        ($WebRequest.Content | ConvertFrom-Json -Depth 100).$ResponseRes | ForEach-Object { $Output.Add($_) | Out-Null }
                    }
                } until (!$InvokeError)
            }
            else {
                $ModuleError = $InvokeError.InnerException.Message
            }
        }

    }
    end {
        $ErrorActionPreference = "Stop"
        if ($ModuleError) {
            Write-Error $ModuleError
        }
        else {
            Return $Output
        }
    }
}