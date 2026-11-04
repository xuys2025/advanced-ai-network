[CmdletBinding()]
param([string]$Gateway,[string]$Adapter,[string]$Desktop,[string]$Code,[int]$ClashPort=0,[switch]$CheckOnly,[switch]$Hold)
. (Join-Path $PSScriptRoot 'compatibility\Runtime.ps1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$package=$PSScriptRoot;$name='AdvancedAINetworkLanGateway';$root=Join-Path $env:ProgramData $name
$appParent=Join-Path $env:LOCALAPPDATA 'Programs\AdvancedAINetwork';$appRoot=Join-Path $appParent 'electron-v0.6.9-lan.1'
$runKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$result=[ordered]@{success=$false;version='0.6.9-lan.1';check_only=[bool]$CheckOnly}
$backup=$null;$stopped=$false;$created=$false;$oldRun=$null;$uiStopped=$false;$oldRoot=$null;$oldLauncher=$null
function Save-Json($path,$data){[IO.File]::WriteAllText($path,($data|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))}
function No-Link([string]$path){if((Test-Path -LiteralPath $path)-and((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw ('目录不能是链接：'+$path)}}
function Driver-Check([string]$path){if(!(Test-Path -LiteralPath $path)-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-ne'8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'-or(Get-AuthenticodeSignature -LiteralPath $path).Status-ne'Valid'){throw 'WinDivert 驱动版本或签名不符；不会覆盖其他软件的驱动。'}}
function Healthy([bool]$expected){$end=[DateTime]::UtcNow.AddSeconds(50);do{Start-Sleep -Milliseconds 500;try{$s=Get-Content (Join-Path $root 'status.json') -Raw -Encoding UTF8|ConvertFrom-Json;if($s.ready-eq$expected-and$s.capturing-and([DateTime]::UtcNow-[DateTime]::Parse($s.updated_utc).ToUniversalTime()).TotalSeconds-lt 3){return $s}}catch{}}while([DateTime]::UtcNow-lt$end);throw '网关服务未就绪，请查看 ProgramData\AdvancedAINetworkLanGateway\status.json。'}
try{
    if(![Environment]::Is64BitOperatingSystem-or![Environment]::Is64BitProcess){throw '请使用 Windows 10/11 x64 和 64 位 PowerShell。'}
    $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if(!$admin-and!$CheckOnly){
        $command="& '"+$PSCommandPath.Replace("'","''")+"' -Hold"
        foreach($key in @('Gateway','Adapter','Desktop','Code')){if($PSBoundParameters.ContainsKey($key)){$command+=' -'+$key+" '"+([string]$PSBoundParameters[$key]).Replace("'","''")+"'"}}
        if($ClashPort){$command+=' -ClashPort '+$ClashPort}
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $child=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -PassThru
        $child.WaitForExit();exit $child.ExitCode
    }
    foreach($legacyKey in @('LegacyGatewayService','LegacyGuardService')){if(Get-Service -Name (Get-AiCompatibility $legacyKey) -ErrorAction SilentlyContinue){throw '检测到旧版后台，请先完成旧版迁移，避免两套后台争用同一端口。本安装器不会解除已有保护。'}}
    $discovery=& (Join-Path $package 'Tools\SetupInspect.exe') --discover
    if($LASTEXITCODE-ne 0){throw '无法识别本机 高级 AI 程序和网卡。'};$discovery=$discovery|ConvertFrom-Json
    if(!$Gateway){if($CheckOnly){throw 'CheckOnly 需要 -Gateway 参数。'};$Gateway=Read-Host '请输入你自己的局域网出口网关 IPv4 地址'}
    if(!$Desktop){$Desktop=$discovery.desktop};if(!$Code){$Code=$discovery.code}
    if(!$Desktop-and!$CheckOnly){$Desktop=Read-Host '未找到 高级 AI 桌面端，请输入官方 目标程序 的完整路径'}
    if(!$Code-and!$CheckOnly){$Code=Read-Host '未找到原生 CC CLI，请输入官方 目标程序 的完整路径'}
    if(!$Adapter){$candidates=@($discovery.adapters);if($candidates.Count-eq 1){$Adapter=$candidates[0].id}else{if($CheckOnly){throw '存在多个网卡，请指定 -Adapter 的 GUID。'};for($i=0;$i-lt$candidates.Count;$i++){Write-Host ("{0}: {1} [{2}]"-f($i+1),$candidates[$i].name,($candidates[$i].addresses-join', '))};$choice=0;if(![int]::TryParse((Read-Host '选择以太网网卡编号'),[ref]$choice)-or$choice-lt 1-or$choice-gt$candidates.Count){throw '无效网卡编号。'};$Adapter=$candidates[$choice-1].id}}
    if(!$ClashPort){$proxy=Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue;if($proxy-match'^(?:http=)?(?:127\.0\.0\.1|localhost):(\d+)(?:;|$)'){$ClashPort=[int]$Matches[1]}else{$ClashPort=7897;if(!$CheckOnly){$answer=Read-Host 'Clash 本机混合/HTTP 端口（回车使用 7897）';if($answer){$ClashPort=[int]$answer}}}}
    if($ClashPort-lt 1-or$ClashPort-gt 65535-or($ClashPort-ge 17891-and$ClashPort-le 17896)-or$ClashPort-eq 34010){throw 'Clash 端口无效或与专用入口冲突。'}
    $inspection=& (Join-Path $package 'Tools\SetupInspect.exe') $Gateway $Adapter $Desktop $Code
    if($LASTEXITCODE-ne 0){throw '网关、网卡或程序签名预检查失败。'};$inspection=$inspection|ConvertFrom-Json
    Driver-Check (Join-Path $package 'Gateway\WinDivert64.sys')
    if((Get-FileHash (Join-Path $package 'Gateway\WinDivert.dll')).Hash.ToLowerInvariant()-ne'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'){throw 'WinDivert DLL 校验失败。'}
    if(!(Test-Path -LiteralPath "$env:WINDIR\System32\Npcap\wpcap.dll")){throw '请先从 https://npcap.com/ 自行安装 Npcap，然后重新运行安装。'}
    $existing=Get-CimInstance Win32_Service -Filter "Name='$name'"
    if($existing-and$existing.PathName.Trim('"')-ne(Join-Path $root 'GatewayService.exe')){throw '同名服务属于其他目录，已保留。'}
    $driver=Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'"
    if($driver){Driver-Check ($driver.PathName.Replace('\??\','').Trim('"'))}
    $result.preflight=$inspection;$result.clash_port=$ClashPort;$result.existing_service=[bool]$existing
    if($CheckOnly){$result.success=$true;$result|ConvertTo-Json -Depth 10;return}
    if(@(Get-CimInstance Win32_Process -Filter (Get-AiCompatibility 'S_ea96197f8c65b8')).Count){throw '请自行完全退出 高级 AI 桌面端 和 CC CLI，再安装；安装器不会强行关闭它们。'}
    $oldRelay=Get-Service AdvancedAINetworkDesktopRelay -ErrorAction SilentlyContinue;if($oldRelay-and$oldRelay.Status-eq'Running'){throw '旧隧道转发后台仍在运行，请先停用旧版本；本安装器不迁移旧隧道。'}
    foreach($path in @($root,$appParent,$appRoot)){No-Link $path}
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if(Test-Path -LiteralPath $root){$directoryOwner=(Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value;if($directoryOwner-notin@('S-1-5-18','S-1-5-32-544')){throw '服务目录未由管理员拥有，拒绝写入。'}}
    $oldRun=Get-ItemPropertyValue $runKey -Name AdvancedAIPrivateNetwork -ErrorAction SilentlyContinue
    if($oldRun){if($oldRun-notmatch'^"([^"]+\\AdvancedAINetworkLauncher\.exe)" --startup$'){throw '已有启动项不属于此安装器。'};$oldLauncher=[IO.Path]::GetFullPath($Matches[1]);$oldRoot=Split-Path -Parent $oldLauncher;if(!$oldRoot.StartsWith([IO.Path]::GetFullPath($appParent)+'\',[StringComparison]::OrdinalIgnoreCase)){throw '已有启动项指向其他程序目录。'}}
    $beforeProxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'|Select-Object ProxyEnable,ProxyServer,AutoConfigURL
    $beforeRoute=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Sort-Object InterfaceIndex,NextHop|Select-Object InterfaceIndex,NextHop,RouteMetric)
    $null=New-Item -ItemType Directory -Path $root -Force
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($owner),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $root -AclObject $acl
    foreach($seed in @(@('managed-rules.json','RuleSeed'),@('managed-domains.json','DomainSeed'))){$seedPath=Join-Path $root $seed[0];if(!(Test-Path -LiteralPath $seedPath)){[IO.File]::WriteAllText($seedPath,(Get-AiCompatibility $seed[1]),[Text.UTF8Encoding]::new($false))}}
    $guard=(& (Join-Path $package 'Guard\Guard-Setup.ps1') -Action Status)|ConvertFrom-Json
    if(!$guard.protected-or!$guard.tun_ready-or!$guard.dns_64_65_blocked-or!$guard.keyword_system_enabled-or!(Test-Path -LiteralPath (Join-Path $env:ProgramData 'AdvancedAINetworkGuard\AdvancedAINetworkGuard.exe'))-or(Get-FileHash -LiteralPath (Join-Path $env:ProgramData 'AdvancedAINetworkGuard\AdvancedAINetworkGuard.exe')).Hash-ne(Get-FileHash -LiteralPath (Join-Path $package 'Guard\AdvancedAINetworkGuard.exe')).Hash){
        & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $package 'Guard\Guard-Setup.ps1') -Action Enable -SystemKeywords
        if($LASTEXITCODE-ne 0){throw '域名保护安装失败；已建立的保护规则会保留，详见修复说明。'}
        $deadline=[DateTime]::UtcNow.AddSeconds(40);do{Start-Sleep -Seconds 1;$guard=(& (Join-Path $package 'Guard\Guard-Setup.ps1') -Action Status)|ConvertFrom-Json}while(!$guard.tun_ready-and[DateTime]::UtcNow-lt$deadline)
        if(!$guard.protected-or!$guard.tun_ready){throw '请等待域名保护服务恢复后重试。'}
    }
    if($existing){$backup=Join-Path $root ('backup-'+(Get-Date -Format yyyyMMdd-HHmmss));$null=New-Item -ItemType Directory -Path $backup;foreach($file in @('GatewayService.exe','ProxyBridgeCore.dll','WinDivert.dll','config.json','intent.json')){if(Test-Path (Join-Path $root $file)){Copy-Item (Join-Path $root $file) $backup}};Stop-Service $name -ErrorAction Stop;$stopped=$true}
    if($oldRoot){$owned=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath-and$_.ExecutablePath.StartsWith($oldRoot+'\',[StringComparison]::OrdinalIgnoreCase)});foreach($p in $owned|Sort-Object @{Expression={if($_.Name-eq'AdvancedAINetworkLauncher.exe'){0}else{1}}}){Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue};$uiStopped=$true}
    $null=New-Item -ItemType Directory -Path $appRoot -Force
    foreach($item in Get-ChildItem (Join-Path $package 'App')){Copy-Item -LiteralPath $item.FullName -Destination $appRoot -Recurse -Force}
    & icacls.exe $appRoot /grant '*S-1-15-2-1:(OI)(CI)(RX)' /Q|Out-Null;if($LASTEXITCODE-ne 0){throw '无法为 Electron 沙箱设置读取权限。'}
    foreach($file in @('GatewayService.exe','ProxyBridgeCore.dll','WinDivert.dll','WinDivert64.sys')){Copy-Item -LiteralPath (Join-Path $package ('Gateway\'+$file)) -Destination $root -Force}
    Save-Json (Join-Path $root 'config.json') @{owner_sid=$owner;desktop_image=$Desktop;code_image=$Code;adapter=$Adapter;gateway=$Gateway;front_port=$ClashPort}
    Save-Json (Join-Path $root 'intent.json') @{enabled=$true}
    if(!$driver){& "$env:WINDIR\System32\sc.exe" create WinDivert type= kernel start= demand binPath= ('"'+(Join-Path $root 'WinDivert64.sys')+'"')|Out-Null;if($LASTEXITCODE-ne 0){throw '无法注册已签名的 WinDivert 驱动。'}}
    if((Get-Service WinDivert).Status-ne'Running'){Start-Service WinDivert}
    if(!$existing){& "$env:WINDIR\System32\sc.exe" create $name type= own start= auto binPath= ('"'+(Join-Path $root 'GatewayService.exe')+'"') depend= 'BFE/MpsSvc/AdvancedAINetworkDomainGuard' DisplayName= '高级 AI 专用网络 LAN Gateway'|Out-Null;if($LASTEXITCODE-ne 0){throw '服务注册失败。'};$created=$true}else{Set-Service $name -StartupType Automatic}
    & "$env:WINDIR\System32\sc.exe" failure $name reset= 86400 actions= 'restart/3000/restart/5000/restart/15000'|Out-Null
    if($LASTEXITCODE-ne 0){throw '服务恢复策略设置失败。'}
    & "$env:WINDIR\System32\sc.exe" failureflag $name 1|Out-Null;if($LASTEXITCODE-ne 0){throw '服务恢复标志设置失败。'}
    Start-Service $name;$state=Healthy $true
    & (Join-Path $package 'Tools\ProtectionAudit.exe') (Join-Path $root 'dns-verification.json');if($LASTEXITCODE-ne 0){throw 'DNS 保护测试失败。'}
    $afterProxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'|Select-Object ProxyEnable,ProxyServer,AutoConfigURL
    $afterRoute=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Sort-Object InterfaceIndex,NextHop|Select-Object InterfaceIndex,NextHop,RouteMetric)
    if(($beforeProxy|ConvertTo-Json -Compress)-ne($afterProxy|ConvertTo-Json -Compress)-or($beforeRoute|ConvertTo-Json -Compress)-ne($afterRoute|ConvertTo-Json -Compress)){throw '检测到系统代理或默认路由变化，请检查其他网络软件。'}
    $launcher=Join-Path $appRoot 'AdvancedAINetworkLauncher.exe';$null=New-Item -Path $runKey -Force
    Set-ItemProperty $runKey -Name AdvancedAIPrivateNetwork -Value ('"'+$launcher+'" --startup')
    $shell=New-Object -ComObject WScript.Shell
    try{$shortcut=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) '高级 AI 专用网络.lnk'));$shortcut.TargetPath=$launcher;$shortcut.WorkingDirectory=$appRoot;$shortcut.Save()}finally{[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)|Out-Null}
    $null=New-Item -ItemType Directory -Path (Join-Path $env:LOCALAPPDATA 'AdvancedAIPrivateNetwork') -Force
    $result.success=$true;$result.gateway=$Gateway;$result.exit=$state.last_exit;$result.client=$appRoot;$result.backup=$backup
    Write-Host '安装完成。请从桌面快捷方式打开界面，并按说明合并 Clash 规则。' -ForegroundColor Green
    Write-Host '安装器没有启动真实 高级 AI 程序，也没有修改 Clash、系统默认网关或网卡 IPv6 设置。'
}catch{
    $result.error=$_.Exception.Message;$result.line=$_.InvocationInfo.ScriptLineNumber
    if($stopped-and$backup){try{Stop-Service $name -ErrorAction SilentlyContinue;foreach($file in Get-ChildItem $backup -File){Copy-Item -LiteralPath $file.FullName -Destination $root -Force};Start-Service $name;$result.restored_previous_service=$true}catch{$result.restore_error=$_.Exception.Message}}
    elseif($created){Stop-Service $name -ErrorAction SilentlyContinue;Set-Service $name -StartupType Manual -ErrorAction SilentlyContinue}
    if($oldRun){Set-ItemProperty $runKey -Name AdvancedAIPrivateNetwork -Value $oldRun}
    Write-Host ('安装未完成：'+$result.error) -ForegroundColor Red
    Write-Host '已有域名保护会保留。修好配置后重跑安装；要解除限制请阅读 Uninstall.ps1 的说明。'
}finally{
    if(!$CheckOnly){try{Save-Json (Join-Path $package 'install-result.json') $result}catch{};if($Hold){$null=Read-Host '按回车关闭'}}
}
if(!$result.success){exit 1}
