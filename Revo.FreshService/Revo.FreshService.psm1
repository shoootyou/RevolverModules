
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
        $ResponseRes = ($ResourceURL.Substring(0,$ResourceURL.IndexOf("?")).Replace("/","")).ToLower()
        
        $WebRequest = Invoke-WebRequest -Method GET -Uri $FinalURL -Authentication Basic -Credential $Credentials -ErrorVariable InvokeError
        if($null -ne $WebRequest){
            [System.Collections.ArrayList]$Output = @()
            ($WebRequest.Content | ConvertFrom-Json -Depth 10).$ResponseRes | ForEach-Object { $Output.Add($_) | Out-Null }
            if ($null -ne $WebRequest.Headers.Link) {
                do {
                    if([int]($WebRequest.Headers.'X-Ratelimit-Remaining'[0]) -lt 10){
                        Write-Warning "============ Throttling your request, please wait! ============"
                        Start-Sleep -Seconds 90
                    }
                    $WebRequest = Invoke-WebRequest -Method GET -Uri (($WebRequest.Headers.Link -split ";")[0].Replace("<", "").Replace(">", "")) -Authentication Basic -Credential $Credentials -ErrorVariable InvokeError
                    ($WebRequest.Content | ConvertFrom-Json -Depth 10).$ResponseRes | ForEach-Object { $Output.Add($_) | Out-Null }
                } until ($null -eq $WebRequest.Headers.Link)
            }
        }

        if ($InvokeError.Count -gt 0) {
            if ($InvokeError.ErrorRecord.ErrorDetails) {
                switch (($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).code) {
                    access_denied { $ModuleError = ($InvokeError.ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 10).Message }
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