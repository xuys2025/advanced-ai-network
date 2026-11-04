param([string]$Report=(Join-Path $PSScriptRoot 'check-result.json'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$result=[ordered]@{success=$false;read_only=$true;checked_utc=[DateTime]::UtcNow.ToString('o')}
try{
    $state=Get-Content (Join-Path $env:ProgramData 'AdvancedAINetworkLanGateway\status.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $result.state=$state
    if(!$state.ready-or([DateTime]::UtcNow-[DateTime]::Parse($state.updated_utc).ToUniversalTime()).TotalSeconds-gt 5){throw 'The gateway is not ready or its heartbeat is stale.'}
    & (Join-Path $PSScriptRoot 'Tools\ProtectionAudit.exe') ($Report+'.dns.json');if($LASTEXITCODE-ne 0){throw 'DNS verification failed.'}
    $result.dns=Get-Content ($Report+'.dns.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $policy=(& (Join-Path $PSScriptRoot 'Guard\Guard-Setup.ps1') -Action Status)|ConvertFrom-Json;$result.domain_policy=$policy
    if(!$policy.protected-or$policy.covered-ne $policy.required){throw 'The independent domain policy is incomplete.'}
    $proxyEnabled=Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue;$result.system_proxy_enabled=[bool]$proxyEnabled
    $args=@('--silent','--show-error','--fail','--max-time','12','--noproxy','*','https://api.ipify.org/')
    $result.protected_direct_exit=(& "$env:WINDIR\System32\curl.exe" @args 2>$null)-join'';if($LASTEXITCODE-ne 0){throw 'Protected direct HTTPS request failed.'}
    if($proxyEnabled){$result.protected_clash_exit=(& "$env:WINDIR\System32\curl.exe" --silent --show-error --fail --max-time 12 --proxy ('http://127.0.0.1:'+$state.front_port) https://api.ipify.org/ 2>$null)-join'';if($LASTEXITCODE-ne 0){throw 'Protected HTTPS through Clash failed; check the merged rules.'}}
    $result.success=$true
}catch{$result.error=$_.Exception.Message}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Report),($result|ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
$result|Select-Object success,error,checked_utc|Format-List
if(!$result.success){exit 1}
