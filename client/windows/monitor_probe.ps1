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
    return $cfg
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
    return Invoke-WebRequest @params
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
    $headers = @{
        'X-Probe-Token' = [string]$Cfg.ProbeToken
        'Accept' = 'application/json'
    }
    $configResponse = Invoke-ProbeRequest -Method Get -Url "$baseUrl/api/v1/external-monitor-probe/config" -Headers $headers -TlsInsecure:$tlsInsecure
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
    $payload = @{ results = $results } | ConvertTo-Json -Compress -Depth 4
    Invoke-ProbeRequest -Method Post -Url "$baseUrl/api/v1/external-monitor-probe/push" -Headers $headers -Body $payload -TlsInsecure:$tlsInsecure | Out-Null
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
        }
    }
    if ($RunOnce) {
        if ($cycleFailed) { exit 1 }
        break
    }
    Start-Sleep -Seconds $loopInterval
} while ($true)
