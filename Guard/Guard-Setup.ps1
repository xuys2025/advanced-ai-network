[CmdletBinding()]
param([ValidateSet('Enable','Disable','Status','Repair')][string]$Action='Status',[switch]$SystemKeywords)
. (Join-Path $PSScriptRoot 'compatibility\Runtime.ps1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$serviceName='AdvancedAINetworkDomainGuard'
$comment='AdvancedAIPrivateNetwork-v0.2'
$guardPath=Join-Path $env:ProgramData 'AdvancedAINetworkGuard'
$guardExe=Join-Path $guardPath 'AdvancedAINetworkGuard.exe'
$enabledMarker=Join-Path $guardPath 'protection-enabled'
$keywordMarker=Join-Path $guardPath 'system-keyword-dns'
$keywordMode=$SystemKeywords -or (Test-Path -LiteralPath $keywordMarker)
$tunMarker=Join-Path $guardPath 'selective-tun-enabled'
$tunPrefix='198.19.64.0/18'
$tunAdapter='AdvancedAINetwork-TUN'
$tunFirewall='AdvancedAINetwork-SelectiveTun-Block'
$tunGroup='AdvancedAINetworkSelectiveTun'
$script:logSafe=$false
$script:upgradeStopped=$false
$script:backupValid=$false
trap {
    $failure=$_.Exception.Message
    if($script:upgradeStopped){try{if($script:backupValid){Copy-Item -LiteralPath (Join-Path $guardPath 'AdvancedAINetworkGuard.previous.exe') -Destination $guardExe -Force};Start-Service -Name $serviceName -ErrorAction Stop}catch{}}
    if($script:logSafe){[IO.File]::WriteAllText((Join-Path $guardPath 'last-operation-error.txt'),$failure,(New-Object Text.UTF8Encoding($false)))}
    Write-Error -Message $failure -ErrorAction Continue
    exit 1
}
$roots=@((Get-AiCompatibility 'S_d318762d9a7b1e'),(Get-AiCompatibility 'S_c55d5f6562819e'),'antspace.dev','clau.de',(Get-AiCompatibility 'S_743e483ae01f1f'),(Get-AiCompatibility 'S_3c3a75765581d1'),(Get-AiCompatibility 'S_ba35b59b5869e8'),(Get-AiCompatibility 'S_b55da41d0fb07a'),(Get-AiCompatibility 'S_c3b2d321f93f6b'),(Get-AiCompatibility 'S_cceb19833d60dc'),(Get-AiCompatibility 'S_9bf2a517ed3cdf'),(Get-AiCompatibility 'S_4d8d78a2b2b457'),(Get-AiCompatibility 'S_a1101ea07e3e93'),(Get-AiCompatibility 'S_62e4eb09895085'),'modelcontextprotocol.com','modelcontextprotocol.io','modelcontextprotocol.net','modelcontextprotocol.org','ant.dev',(Get-AiCompatibility 'S_e8d2487918725c'),(Get-AiCompatibility 'S_377781691d8cda'),(Get-AiCompatibility 'S_ea80aaae921557'),(Get-AiCompatibility 'S_2d7a1683632e95'),'intercom.io','intercomcdn.com','interface.feedback','lcicat.org','lcicollections.org','mcpservertest.online','muthos.com','sentry.io','sillylittleguy.org','statsigapi.net')
$exact=@('api.ipify.org','icanhazip.com','ifconfig.me','ip.net.coffee',(Get-AiCompatibility 'S_783a5375a32dd3'),(Get-AiCompatibility 'S_7361a0b35b1d80'),(Get-AiCompatibility 'S_1e461caa6d3581'),'browser-intake-us5-datadoghq.com','cdn.growthbook.io','cdn.usefathom.com',(Get-AiCompatibility 'S_10aec8d3389d2c'),'storage.googleapis.com')
$namespaces=@($roots | ForEach-Object {$_;'.'+$_})+$exact
if($namespaces.Count -ne 78 -or $namespaces -contains '.'){throw 'Invalid protected namespace allowlist.'}
$policyDomains=[string[]]@($roots+$exact+@('keyword:datadog','keyword:sentry','keyword:sift'));[Array]::Sort($policyDomains,[StringComparer]::Ordinal)
$dispatchDns='127.0.0.2'
$managed=Join-Path $env:ProgramData 'AdvancedAINetworkLanGateway\managed-domains.json'
if($keywordMode -and (Test-Path -LiteralPath $managed)){
    $dispatchDns='127.0.0.3'
    $liveDomains=(Get-Content -LiteralPath $managed -Raw -Encoding UTF8|ConvertFrom-Json).rules[0]
    $policyDomains=[string[]]@(@($liveDomains.domain_suffix)+@($liveDomains.domain)+@($liveDomains.domain_keyword|ForEach-Object {'keyword:'+$_}))
    [Array]::Sort($policyDomains,[StringComparer]::Ordinal)
}
$policyDigest=[Security.Cryptography.SHA256]::Create()
try{$policyHash=([BitConverter]::ToString($policyDigest.ComputeHash([Text.Encoding]::ASCII.GetBytes(($policyDomains -join "`n"))))).Replace('-','').ToLowerInvariant()}finally{$policyDigest.Dispose()}
function OwnedRules { @(Get-DnsClientNrptRule | Where-Object {$_.Comment -eq $comment}) }
$script:loopIfIndex=$null
function TunLoopIndex {
    if($null -eq $script:loopIfIndex){$script:loopIfIndex=(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '127.0.0.1' -ErrorAction Stop).InterfaceIndex}
    $script:loopIfIndex
}
function TunFallback([string]$Store){@(Get-NetRoute -DestinationPrefix $tunPrefix -PolicyStore $Store -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -eq (TunLoopIndex) -and $_.NextHop -eq '0.0.0.0' -and $_.RouteMetric -eq 4096})}
function AssertTunRangeAvailable {
    $owned=Test-Path -LiteralPath $tunMarker
    foreach($route in @(Get-NetRoute -AddressFamily IPv4)){
        $parts=$route.DestinationPrefix.Split('/');$bits=[int]$parts[1]
        if($bits -eq 0 -or $bits -eq 1){continue}
        $bytes=[Net.IPAddress]::Parse($parts[0]).GetAddressBytes();$number=([uint64]$bytes[0]*16777216)+([uint64]$bytes[1]*65536)+([uint64]$bytes[2]*256)+$bytes[3]
        $size=[Math]::Pow(2,32-$bits);$low=[Math]::Floor($number/$size)*$size;$high=$low+$size-1
        $start=3323150336L;$end=3323166719L
        if($low -gt $end -or $high -lt $start){continue}
        if($owned -and $route.DestinationPrefix -eq $tunPrefix -and (($route.InterfaceIndex -eq (TunLoopIndex) -and $route.NextHop -eq '0.0.0.0' -and $route.RouteMetric -eq 4096) -or $route.InterfaceAlias -eq $tunAdapter)){continue}
        if($owned -and $route.DestinationPrefix -eq '198.19.127.255/32' -and $route.InterfaceIndex -eq (TunLoopIndex) -and $route.NextHop -eq '0.0.0.0' -and [int]$route.Protocol -eq 2 -and @(TunFallback 'ActiveStore').Count -gt 0){continue}
        throw ('The dedicated TUN range conflicts with an existing route: '+$route.DestinationPrefix+' on '+$route.InterfaceAlias)
    }
    $firewall=Get-NetFirewallRule -Name $tunFirewall -ErrorAction SilentlyContinue
    if($null -ne $firewall -and (!$owned -or $firewall.Group -ne $tunGroup)){throw 'The dedicated TUN firewall name belongs to another configuration.'}
}
function RepairTunSafety {
    if(!(Test-Path -LiteralPath $tunMarker)){throw 'Selective TUN has not been installed; use Enable to upgrade protection.'}
    AssertTunRangeAvailable
    if(@(TunFallback 'PersistentStore').Count -eq 0){
        $routeError=$null
        try{$null=New-NetRoute -DestinationPrefix $tunPrefix -InterfaceIndex (TunLoopIndex) -NextHop '0.0.0.0' -RouteMetric 4096}catch{$routeError=$_}
        if(@(TunFallback 'PersistentStore').Count -eq 0){if($null -ne $routeError){throw $routeError};throw 'Persistent protected loopback route was not created.'}
    }
    if(@(TunFallback 'ActiveStore').Count -eq 0){$null=New-NetRoute -DestinationPrefix $tunPrefix -InterfaceIndex (TunLoopIndex) -NextHop '0.0.0.0' -RouteMetric 4096 -PolicyStore ActiveStore}
    $aliases=@(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.InterfaceIndex -ne (TunLoopIndex) -and $_.InterfaceAlias -ne $tunAdapter} | Select-Object -ExpandProperty InterfaceAlias -Unique)
    if($aliases.Count -eq 0){throw 'Waiting for uplink interfaces; the protected loopback route is retained.'}
    if($null -eq (Get-NetFirewallRule -Name $tunFirewall -ErrorAction SilentlyContinue)){$null=New-NetFirewallRule -Name $tunFirewall -DisplayName '高级 AI 专用网络 protected address range' -Group $tunGroup -Direction Outbound -Action Block -Profile Any -RemoteAddress $tunPrefix -InterfaceAlias $aliases}
    else{$null=Set-NetFirewallRule -Name $tunFirewall -Direction Outbound -Action Block -Profile Any -RemoteAddress $tunPrefix -InterfaceAlias $aliases -Enabled True}
}
function RemoveTunSafety {
    if(!(Test-Path -LiteralPath $tunMarker)){return}
    $rule=Get-NetFirewallRule -Name $tunFirewall -ErrorAction SilentlyContinue
    if($null -ne $rule -and $rule.Group -eq $tunGroup){Remove-NetFirewallRule -Name $tunFirewall}
    foreach($store in @('PersistentStore','ActiveStore')){foreach($route in @(TunFallback $store)){$route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue}}
    Remove-Item -LiteralPath $tunMarker -Force
}
function AssertNoConflicts {
    $claimed=@($namespaces)
    if($keywordMode){$claimed+='.'}
    $conflicts=@(Get-DnsClientNrptRule | Where-Object {$_.Comment -ne $comment -and @($_.Namespace | Where-Object {$claimed -contains $_}).Count -gt 0})
    if($conflicts.Count -gt 0){throw '存在其他软件或管理员设置的同名 DNS 策略。请先停用旧 高级 AI 专用客户端并检查冲突，本程序不会删除它们。'}
}
function Status {
    $rules=@(OwnedRules)
    $effective=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    $service=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $covered=0
    foreach($name in $namespaces){
        $match=@($effective | Where-Object {($_.Namespace -contains $name) -and ($_.NameServers -contains $dispatchDns)})
        if($match.Count -gt 0){$covered++}
    }
    $required=$namespaces.Count
    $keywordSystem=Test-Path -LiteralPath $keywordMarker
    if($keywordSystem){$required++;if(@($effective|Where-Object {$_.Namespace -contains '.' -and $_.NameServers -contains '127.0.0.3'}).Count){$covered++}}
    # PersistentStore and firewall queries require elevation. The SYSTEM service
    # publishes a short-lived result only after its privileged repair succeeds.
    $safety=$false
    $health=$null;$tunReady=$false;$blocked=$false
    $healthPath=Join-Path $guardPath 'guard-status.json'
    $stream=$null;$reader=$null
    try{$stream=[IO.File]::Open($healthPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));$reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8);$health=$reader.ReadToEnd()|ConvertFrom-Json;$updated=if($health.updated_utc -is [DateTime]){$health.updated_utc.ToUniversalTime()}else{[DateTime]::Parse($health.updated_utc).ToUniversalTime()};$age=([DateTime]::UtcNow-$updated).TotalSeconds;$fresh=($age -ge 0 -and $age -lt 15 -and $health.version -eq '0.4.1' -and $health.policy_hash -eq $policyHash);$tunReady=($fresh -and $health.tun_ready);$blocked=($fresh -and $health.dns_64_65_blocked);$safety=($fresh -and $health.network_safety_ready)}catch{}finally{if($null -ne $reader){$reader.Dispose()}elseif($null -ne $stream){$stream.Dispose()}}
    [ordered]@{expected_policy_hash=$policyHash;owned_rules=$rules.Count;covered=$covered;required=$required;keyword_system_enabled=$keywordSystem;running=($null -ne $service -and $service.Status -eq 'Running');protected=($covered -eq $required -and $null -ne $service -and $service.Status -eq 'Running' -and $safety);tun_safety=$safety;tun_ready=$tunReady;dns_64_65_blocked=$blocked;health=$health} | ConvertTo-Json -Depth 5 -Compress
}
if($Action -eq 'Status'){Status;exit 0}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw '仅安装或解除域名保护需要管理员权限，请通过客户端按钮操作。'}
if(Test-Path -LiteralPath $guardPath){
    $directory=Get-Item -LiteralPath $guardPath -Force
    if(($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw '域名保护安装目录不能是链接或重解析点。'}
    $owner=(Get-Acl -LiteralPath $guardPath).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw '域名保护安装目录已被普通用户预占。请由管理员检查并移走该目录后再安装。'}
    $script:logSafe=$true
}
if($Action -eq 'Disable'){
    # Deliberately no automatic rollback/unlock on errors elsewhere.
    $service=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if($null -ne $service){Stop-Service -Name $serviceName -ErrorAction Stop;Set-Service -Name $serviceName -StartupType Manual}
    if(Test-Path -LiteralPath $enabledMarker){Remove-Item -LiteralPath $enabledMarker -Force}
    if(Test-Path -LiteralPath $keywordMarker){Remove-Item -LiteralPath $keywordMarker -Force}
    foreach($rule in (OwnedRules)){Remove-DnsClientNrptRule -Name $rule.Name -Force}
    RemoveTunSafety
    Clear-DnsClientCache
    Status
    exit 0
}
# Never replace existing namespace policy installed by another VPN or administrator.
if($Action -ne 'Repair'){AssertNoConflicts}
function RepairRules {
    $lockPath=Join-Path $guardPath 'policy.lock'
    $policyLock=$null
    for($attempt=0;$attempt -lt 30 -and $null -eq $policyLock;$attempt++){try{$policyLock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch [IO.IOException]{Start-Sleep -Milliseconds 100}}
    if($null -eq $policyLock){throw '域名策略正在维护，稍后重试。'}
    try{
        AssertNoConflicts
        $existingOwned=@(OwnedRules)
        if(Test-Path -LiteralPath $keywordMarker){
            $any=@($existingOwned|Where-Object {$_.Namespace -contains '.'})
            if(!$any.Count){$null=Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.3' -Comment $comment -DisplayName '高级 AI 专用网络 keyword DNS'}
            else{foreach($r in $any){if(@($r.NameServers).Count -ne 1 -or $r.NameServers -notcontains '127.0.0.3'){Set-DnsClientNrptRule -Name $r.Name -NameServers '127.0.0.3'}}}
        }
        foreach($name in $namespaces){
            $matching=@($existingOwned | Where-Object {$_.Namespace -contains $name})
            if($matching.Count -eq 0){$null=Add-DnsClientNrptRule -Namespace $name -NameServers $dispatchDns -Comment $comment -DisplayName ('高级 AI 专用网络 '+$name)}
            else{foreach($rule in $matching){$servers=@($rule.NameServers);if($servers.Count -ne 1 -or $servers[0] -ne $dispatchDns){Set-DnsClientNrptRule -Name $rule.Name -NameServers $dispatchDns}}}
        }
    }finally{$policyLock.Dispose()}
}
if($Action -eq 'Repair'){
    if(!(Test-Path -LiteralPath $enabledMarker)){throw 'Domain protection is disabled.'}
    [Console]::Error.WriteLine('guard-stage DNS policy')
    RepairRules
    [Console]::Error.WriteLine('guard-stage protected routes and firewall')
    RepairTunSafety
    [Console]::Error.WriteLine('guard-stage effective DNS verification')
    $result=Status
    $coverage=$result|ConvertFrom-Json
    if($coverage.required -lt 1 -or $coverage.covered -ne $coverage.required){throw 'Effective protected DNS rules are incomplete.'}
    $result
    exit 0
}
$sourceExe=Join-Path $PSScriptRoot 'AdvancedAINetworkGuard.exe'
if(!(Test-Path -LiteralPath $sourceExe)){throw '缺少域名保护服务程序，请完整解压客户端。'}
$sourceCore=Join-Path $PSScriptRoot 'core\sing-box.exe'
if(!(Test-Path -LiteralPath $sourceCore) -or (Get-FileHash -LiteralPath $sourceCore).Hash.ToLowerInvariant() -ne '5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf'){throw 'The official selective TUN core is missing or failed verification.'}
$existing=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if($null -ne $existing -and $existing.PathName.Trim('"') -ne $guardExe){throw '发现同名服务但安装路径不同，已停止操作。'}
$null=New-Item -ItemType Directory -Path $guardPath -Force
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach($sidText in @('S-1-5-18','S-1-5-32-544')){
    $sid=New-Object Security.Principal.SecurityIdentifier($sidText)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$usersSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($usersSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $guardPath -AclObject $acl
$script:logSafe=$true
AssertTunRangeAvailable
[IO.File]::WriteAllText($tunMarker,'198.19.64.0/18',(New-Object Text.UTF8Encoding($false)))
RepairTunSafety
if($SystemKeywords){[IO.File]::WriteAllText($keywordMarker,'Apply rule keyword matching to Windows DNS',(New-Object Text.UTF8Encoding($false)))}
RepairRules
if(Test-Path -LiteralPath $guardExe){
    if(((Get-Item -LiteralPath $guardExe -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw '服务程序不能是链接或重解析点。'}
}
$different=!(Test-Path -LiteralPath $guardExe) -or (Get-FileHash -LiteralPath $guardExe).Hash -ne (Get-FileHash -LiteralPath $sourceExe).Hash
$backup=Join-Path $guardPath 'AdvancedAINetworkGuard.previous.exe'
if($different){
    if($null -ne $existing){Stop-Service -Name $serviceName -ErrorAction Stop;(Get-Service $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35));$script:upgradeStopped=$true}
    if(Test-Path -LiteralPath $guardExe){Copy-Item -LiteralPath $guardExe -Destination $backup -Force;$script:backupValid=$true}
    Copy-Item -LiteralPath $sourceExe -Destination $guardExe -Force
}
$protectedCoreDirectory=Join-Path $guardPath 'core'
$null=New-Item -ItemType Directory -Path $protectedCoreDirectory -Force
$protectedCore=Join-Path $protectedCoreDirectory 'sing-box.exe'
if(!(Test-Path -LiteralPath $protectedCore) -or (Get-FileHash -LiteralPath $protectedCore).Hash -ne (Get-FileHash -LiteralPath $sourceCore).Hash){Copy-Item -LiteralPath $sourceCore -Destination $protectedCore -Force}
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $guardPath 'Guard-Setup.ps1') -Force
$protectedCompatibility=Join-Path $guardPath 'compatibility'
$null=New-Item -ItemType Directory -Path $protectedCompatibility -Force
$sourceCompatibility=Join-Path $PSScriptRoot 'compatibility\Runtime.ps1'
$targetCompatibility=Join-Path $protectedCompatibility 'Runtime.ps1'
if([IO.Path]::GetFullPath($sourceCompatibility)-ne[IO.Path]::GetFullPath($targetCompatibility)){Copy-Item -LiteralPath $sourceCompatibility -Destination $targetCompatibility -Force}
[IO.File]::WriteAllText($enabledMarker,'enabled',(New-Object Text.UTF8Encoding($false)))
$fileAcl=New-Object Security.AccessControl.FileSecurity
$fileAcl.SetAccessRuleProtection($true,$false)
$fileAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach($sidText in @('S-1-5-18','S-1-5-32-544')){
    $sid=New-Object Security.Principal.SecurityIdentifier($sidText)
    $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))
}
$fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($usersSid,'ReadAndExecute','Allow')))
Set-Acl -LiteralPath $guardExe -AclObject $fileAcl
if($null -eq $existing){$null=New-Service -Name $serviceName -BinaryPathName ('"'+$guardExe+'"') -DisplayName '高级 AI 专用网络 域名保护' -StartupType Automatic -Description '仅接收清单域名的本机 DNS，并转入本机专用隧道；不修改其他域名。'}
Set-Service -Name $serviceName -StartupType Automatic
& "$env:SystemRoot\System32\sc.exe" failure $serviceName reset= 86400 actions= restart/1000/restart/3000/restart/10000 | Out-Null
if($LASTEXITCODE -ne 0){throw '无法设置域名保护服务恢复策略。'}
try{
    Start-Service -Name $serviceName
    (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(12))
    $script:upgradeStopped=$false
}catch{
    if($different -and (Test-Path -LiteralPath $backup)){
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $backup -Destination $guardExe -Force
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    }
    throw '新保护服务未启动，已尝试恢复原程序；所有已有 DNS 限制均保留。请检查服务事件记录。'
}
# Create all owned rules in one operation; failures keep already installed protection.
RepairRules
Clear-DnsClientCache
Status
