#Requires -Version 5.1
<#
.SYNOPSIS
    Lightweight internal service probe for Windows — separate from the monitoring agent.
    Fetches push-monitors from the server, checks them locally, pushes results back.
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = $(if ($env:MONITOR_PROBE_CONFIG) { $env:MONITOR_PROBE_CONFIG } else { 'C:\ProgramData\MonitoringProbe\probe.json' }),
    [int]$IntervalSec = 0,
    [switch]$RunOnce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-ProbeLog {
    param([string]$Message)
    $stamp = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
    Write-Output "$stamp $Message"
}

function Read-ProbeConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $cfg = $raw | ConvertFrom-Json
    if (-not $cfg.ServerUrl -or -not $cfg.ProbeToken) {
        throw "ServerUrl and ProbeToken required in $Path"
    }
    $cfg.ServerUrl = ([string]$cfg.ServerUrl).Trim()
    $cfg.ProbeToken = ([string]$cfg.ProbeToken).Trim()
    return $cfg
}

function Escape-ProbeJsonString {
    param([string]$Text)
    if ($null -eq $Text) {
        return ''
    }
    return ($Text -replace '\\', '\\\\' -replace '"', '\"' -replace "`r", '\r' -replace "`n", '\n' -replace "`t", '\t')
}

function ConvertTo-ProbeResultJson {
    param($Result)
    $monitorId = [int]$Result.monitor_id
    $status = Escape-ProbeJsonString ([string]$Result.status)
    $responseMs = [int]$Result.response_ms
    $httpStatusPart = 'null'
    if ($null -ne $Result.http_status -and "$($Result.http_status)" -ne '') {
        try {
            $httpStatusPart = [string]([int]$Result.http_status)
        } catch {
            $httpStatusPart = 'null'
        }
    }
    $errorMessage = ([string]$Result.error_message -replace '[^\x20-\x7E]', ' ').Trim()
    if ($errorMessage.Length -gt 120) {
        $errorMessage = $errorMessage.Substring(0, 120)
    }
    $errorMessage = Escape-ProbeJsonString $errorMessage
    return "{`"monitor_id`":$monitorId,`"status`":`"$status`",`"response_ms`":$responseMs,`"http_status`":$httpStatusPart,`"error_message`":`"$errorMessage`"}"
}

function Get-ProbeResultsJsonArray {
    param([array]$Results)
    $resultParts = @()
    foreach ($result in $Results) {
        $resultParts += (ConvertTo-ProbeResultJson -Result $result)
    }
    return '[' + ($resultParts -join ',') + ']'
}

function Build-ProbePushPayload {
    param(
        [string]$ProbeToken,
        [array]$Results,
        [switch]$UseBase64
    )
    $token = Escape-ProbeJsonString $ProbeToken
    $resultsJson = Get-ProbeResultsJsonArray -Results $Results
    if ($UseBase64) {
        $resultsB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($resultsJson))
        return "{`"probe_token`":`"$token`",`"results_b64`":`"$resultsB64`"}"
    }
    return "{`"probe_token`":`"$token`",`"results`":$resultsJson}"
}

function Invoke-ProbePushAttempt {
    param(
        [string]$Url,
        [string]$Payload,
        [hashtable]$Headers,
        [bool]$TlsInsecure = $false
    )
    Invoke-ProbeRequest -Method Post -Url $Url -Headers $Headers -Body $Payload -TlsInsecure:$TlsInsecure | Out-Null
}

function Invoke-ProbePush {
    param(
        [string]$BaseUrl,
        [string]$ProbeToken,
        [hashtable]$Headers,
        [array]$Results,
        [bool]$TlsInsecure = $false
    )
    $configUrl = "$BaseUrl/api/v1/external-monitor-probe/config"
    $pushUrl = "$BaseUrl/api/v1/external-monitor-probe/push"
    $transientPattern = '502|503|504|Bad Gateway|Gateway Timeout|Service Unavailable'
    $attemptPlans = @(
        @{ Url = $configUrl; Base64 = $true; Label = 'config/base64' },
        @{ Url = $configUrl; Base64 = $false; Label = 'config/plain' },
        @{ Url = $pushUrl; Base64 = $true; Label = 'push/base64' },
        @{ Url = $pushUrl; Base64 = $false; Label = 'push/plain' }
    )
    $lastError = $null
    foreach ($plan in $attemptPlans) {
        $payload = Build-ProbePushPayload -ProbeToken $ProbeToken -Results $Results -UseBase64:([bool]$plan.Base64)
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            try {
                Invoke-ProbePushAttempt -Url $plan.Url -Payload $payload -Headers $Headers -TlsInsecure:$TlsInsecure
                if ($plan.Label -ne 'config/base64') {
                    Write-ProbeLog "Pushed via $($plan.Label)."
                }
                return
            } catch {
                $message = [string]$_.Exception.Message
                $lastError = $message
                if ($attempt -lt 2 -and $message -match $transientPattern) {
                    Write-ProbeLog "Push via $($plan.Label) failed ($message), retrying..."
                    Start-Sleep -Seconds 2
                    continue
                }
                Write-ProbeLog "Push via $($plan.Label) failed ($message), trying next transport..."
                break
            }
        }
    }
    if ($lastError -match $transientPattern -and $Results.Count -gt 1) {
        Write-ProbeLog "Batch push failed ($lastError), pushing $($Results.Count) result(s) individually (base64 via config)..."
        foreach ($result in $Results) {
            $singlePayload = Build-ProbePushPayload -ProbeToken $ProbeToken -Results @($result) -UseBase64
            Invoke-ProbePushAttempt -Url $configUrl -Payload $singlePayload -Headers $Headers -TlsInsecure:$TlsInsecure
        }
        return
    }
    if ($lastError) {
        throw $lastError
    }
    throw 'Probe push failed without details.'
}

function Invoke-ProbeRequest {
    param(
        [string]$Method,
        [string]$Url,
        [hashtable]$Headers,
        [string]$Body = $null,
        [bool]$TlsInsecure = $false
    )
    $params = @{
        Method      = $Method
        Uri         = $Url
        Headers     = $Headers
        TimeoutSec  = 45
        UseBasicParsing = $true
    }
    if ($Body) {
        $params['Body'] = $Body
        $params['ContentType'] = 'application/json'
    }
    if ($TlsInsecure) {
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
}
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }
    try {
        return Invoke-WebRequest @params
    } catch {
        $responseBody = ''
        if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                $reader.Close()
            } catch {
                $responseBody = ''
            }
        }
        if ($responseBody) {
            throw "$($_.Exception.Message) | response: $responseBody"
        }
        throw
    }
}

function Test-HttpMonitor {
    param(
        [int]$MonitorId,
        [string]$TargetUrl,
        $ExpectedStatus,
        [string]$Keyword,
        [int]$TimeoutSec,
        [bool]$TlsVerify = $true
    )
    $url = $TargetUrl
    if ($url -notmatch '^https?://') {
        $url = "https://$url"
    }
    $started = Get-Date
    $status = 'up'
    $errorMessage = ''
    $httpStatus = $null
    try {
        $requestParams = @{
            Uri = $url
            Method = 'Get'
            TimeoutSec = $TimeoutSec
            UseBasicParsing = $true
        }
        if (-not $TlsVerify) {
            if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
                Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
}
"@
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        $response = Invoke-WebRequest @requestParams
        $httpStatus = [int]$response.StatusCode
        $body = [string]$response.Content
        if ($null -ne $ExpectedStatus -and "$ExpectedStatus" -ne '' -and $httpStatus -ne [int]$ExpectedStatus) {
            $status = 'down'
            $errorMessage = "expected HTTP $ExpectedStatus, got $httpStatus"
        } elseif ($Keyword -and $body -notlike "*$Keyword*") {
            $status = 'down'
            $errorMessage = 'keyword not found'
        }
    } catch {
        $status = 'down'
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $httpStatus = [int]$_.Exception.Response.StatusCode
            $errorMessage = "HTTP $httpStatus"
        } else {
            $errorMessage = $_.Exception.Message
        }
    }
    $responseMs = [int]((Get-Date) - $started).TotalMilliseconds
    return @{
        monitor_id = $MonitorId
        status = $status
        response_ms = $responseMs
        http_status = $httpStatus
        error_message = $errorMessage
    }
}

function Test-TcpMonitor {
    param(
        [int]$MonitorId,
        [string]$Target,
        [int]$TimeoutSec
    )
    $hostName = $Target
    $port = 443
    if ($Target -match '^[a-zA-Z]+://') {
        $uri = [Uri]$Target
        $hostName = $uri.Host
        if ($uri.Port -gt 0) { $port = $uri.Port }
    } elseif ($Target -match ':') {
        $parts = $Target.Split(':', 2)
        $hostName = $parts[0].Trim('[]')
        $port = [int]$parts[1]
    }
    $started = Get-Date
    $status = 'up'
    $errorMessage = ''
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($hostName, $port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)) {
            throw "tcp connect timeout"
        }
        $client.EndConnect($async) | Out-Null
        $client.Close()
    } catch {
        $status = 'down'
        $errorMessage = 'tcp connect failed'
    }
    $responseMs = [int]((Get-Date) - $started).TotalMilliseconds
    return @{
        monitor_id = $MonitorId
        status = $status
        response_ms = $responseMs
        http_status = $null
        error_message = $errorMessage
    }
}

function Invoke-ProbeCycle {
    param($Cfg)
    $baseUrl = ($Cfg.ServerUrl).TrimEnd('/')
    $tlsInsecure = $false
    if ($Cfg.PSObject.Properties.Name -contains 'TlsInsecure') {
        $tlsInsecure = [bool]$Cfg.TlsInsecure
    }
    $probeToken = ([string]$Cfg.ProbeToken).Trim()
    $headers = @{
        'X-Probe-Token' = $probeToken
        'Authorization' = "Bearer $probeToken"
        'Accept' = 'application/json'
        'User-Agent' = 'monitoring-push-probe/1.0'
    }
    $configUrl = "$baseUrl/api/v1/external-monitor-probe/config"
    $configBody = (@{ probe_token = $probeToken } | ConvertTo-Json -Compress)
    $configResponse = Invoke-ProbeRequest -Method Post -Url $configUrl -Headers $headers -Body $configBody -TlsInsecure:$tlsInsecure
    $config = $configResponse.Content | ConvertFrom-Json
    $monitors = @($config.monitors)
    if ($monitors.Count -eq 0) {
        Write-ProbeLog 'No push monitors assigned.'
        return
    }
    $results = @()
    foreach ($monitor in $monitors) {
        $monitorType = if ($monitor.monitor_type) { [string]$monitor.monitor_type } else { 'http' }
        $timeoutSec = if ($monitor.timeout_sec) { [int]$monitor.timeout_sec } else { 15 }
        if ($monitorType -eq 'tcp') {
            $results += Test-TcpMonitor -MonitorId ([int]$monitor.id) -Target ([string]$monitor.target_url) -TimeoutSec $timeoutSec
        } else {
            $expected = $monitor.expected_status
            $keyword = if ($monitor.keyword) { [string]$monitor.keyword } else { '' }
            $tlsVerify = $true
            if ($monitor.PSObject.Properties.Name -contains 'tls_verify') {
                $tlsVerify = [bool]$monitor.tls_verify
            }
            $results += Test-HttpMonitor -MonitorId ([int]$monitor.id) -TargetUrl ([string]$monitor.target_url) -ExpectedStatus $expected -Keyword $keyword -TimeoutSec $timeoutSec -TlsVerify:$tlsVerify
        }
    }
    Write-ProbeLog "Pushing $($results.Count) result(s)..."
    Invoke-ProbePush -BaseUrl $baseUrl -ProbeToken $probeToken -Headers $headers -Results $results -TlsInsecure:$tlsInsecure
    Write-ProbeLog "Pushed $($results.Count) result(s)."
}

$cfg = Read-ProbeConfig -Path $ConfigFile
$loopInterval = if ($IntervalSec -gt 0) { $IntervalSec } elseif ($cfg.PSObject.Properties.Name -contains 'IntervalSec' -and [int]$cfg.IntervalSec -gt 0) { [int]$cfg.IntervalSec } else { 300 }
Write-ProbeLog "monitor_probe starting (server=$($cfg.ServerUrl), interval=${loopInterval}s)"
do {
    $cycleFailed = $false
    try {
        Invoke-ProbeCycle -Cfg $cfg
    } catch {
        $cycleFailed = $true
        $errorText = [string]$_.Exception.Message
        Write-ProbeLog "Probe cycle failed: $errorText"
        if ($errorText -match '401|Nicht autorisiert|Unauthorized|invalid_probe_token|missing_probe_token') {
            Write-ProbeLog 'Hint: Probe-Token ungueltig oder fehlt. Token in probe.json pruefen oder im Infoboard unter Service-Monitor neu generieren.'
        } elseif ($errorText -match '502|503|504|Bad Gateway|Gateway Timeout') {
            Write-ProbeLog 'Hint: Infoboard Push-API nicht erreichbar (Proxy/Gateway). POST mit results[] auf /api/v1/external-monitor-probe/config muss erlaubt sein (wie der Token-Test).'
        }
    }
    if ($RunOnce) {
        if ($cycleFailed) { exit 1 }
        break
    }
    Start-Sleep -Seconds $loopInterval
} while ($true)
