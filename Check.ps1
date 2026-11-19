param([string]$Report=(Join-Path $PSScriptRoot 'check-result.json'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$result=[ordered]@{success=$false;read_only=$true;checked_utc=[DateTime]::UtcNow.ToString('o')}
function Read-ExitIPv4([int]$Port){
    $route=if($Port){@('--noproxy','localhost','--proxy',("http://127.0.0.1:"+$Port))}else{@('--noproxy','*')}
    $body=(& "$env:WINDIR\System32\curl.exe" --disable -4 --silent --show-error --fail --max-time 12 @route https://api.ipify.org/)-join ''
    if($LASTEXITCODE){throw "HTTPS exit check failed (proxy port $Port)."}
    $value=$body.Trim()
    return ConvertTo-ExitIPv4 $value
}
function ConvertTo-ExitIPv4([string]$value){
    $ip=$null
    if(![Net.IPAddress]::TryParse($value,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -cne $value){
        throw 'Exit check returned an invalid IPv4 address.'
    }
    return $value
}
function Test-ExitPaths([bool]$UseClash,[int]$ClashPort){
    for($attempt=1;$attempt -le 2;$attempt++){
        $result.gateway_exit=Read-ExitIPv4 17891
        $result.protected_direct_exit=Read-ExitIPv4 0
        $matchesGateway=$result.protected_direct_exit -eq $result.gateway_exit
        if($UseClash){
            $result.protected_clash_exit=Read-ExitIPv4 $ClashPort
            $matchesGateway=$matchesGateway -and $result.protected_clash_exit -eq $result.gateway_exit
        }
        if($matchesGateway){return}
    }
    throw 'Observed exit addresses differ from the dedicated gateway after two checks. See the recorded addresses.'
}
try{
    $state=Get-Content (Join-Path $env:ProgramData 'AdvancedAINetworkLanGateway\status.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $result.state=$state
    if(!$state.ready-or !$state.process_ip_guard_live -or !$state.guard_protected -or $state.exit_protection -ne 'persistent-wfp' -or ([DateTime]::UtcNow-[DateTime]::Parse($state.updated_utc).ToUniversalTime()).TotalSeconds-gt 5){throw 'The gateway is not ready or its heartbeat is stale.'}
    & (Join-Path $PSScriptRoot 'Tools\ProtectionAudit.exe') ($Report+'.dns.json');if($LASTEXITCODE-ne 0){throw 'DNS verification failed.'}
    $result.dns=Get-Content ($Report+'.dns.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $policy=(& (Join-Path $PSScriptRoot 'Guard\Guard-Setup.ps1') -Action Status)|ConvertFrom-Json;$result.domain_policy=$policy
    if(!$policy.protected-or$policy.covered-ne $policy.required){throw 'The independent domain policy is incomplete.'}
    $proxyEnabled=Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue;$result.system_proxy_enabled=[bool]$proxyEnabled
    Test-ExitPaths ([bool]$proxyEnabled) $state.front_port
    $result.success=$true
}catch{$result.error=$_.Exception.Message}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Report),($result|ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
$result|Select-Object success,error,checked_utc|Format-List
if(!$result.success){exit 1}
