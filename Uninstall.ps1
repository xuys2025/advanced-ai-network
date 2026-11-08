param([switch]$RestoreNetwork)
. (Join-Path $PSScriptRoot 'compatibility\Runtime.ps1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$admin){throw '请在当前用户的管理员 PowerShell 中执行此脚本。'}
if(@(Get-CimInstance Win32_Process -Filter (Get-AiCompatibility 'S_ea96197f8c65b8')).Count){throw '请先自行完全退出 高级 AI 桌面端 和 CC CLI。'}
$name='AdvancedAINetworkLanGateway';$root=Join-Path $env:ProgramData $name
$service=Get-CimInstance Win32_Service -Filter "Name='$name'"
if($service-and$service.PathName.Trim('"')-ne(Join-Path $root 'GatewayService.exe')){throw '同名服务属于其他目录，未操作。'}
if($RestoreNetwork-and(Read-Host '将解除本程序的域名、程序和 IP 阻断。请先恢复 Clash 原脚本，再输入 RESTORE')-cne'RESTORE'){throw '已取消。'}
$run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';$startup=Get-ItemPropertyValue $run -Name AdvancedAIPrivateNetwork -ErrorAction SilentlyContinue
$parent=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\AdvancedAINetwork'))+'\'
if($startup-and$startup-match'^"([^"]+\\AdvancedAINetworkLauncher\.exe)" --startup$'){$launcher=[IO.Path]::GetFullPath($Matches[1]);if($launcher.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)){$app=Split-Path -Parent $launcher;$owned=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath-and$_.ExecutablePath.StartsWith($app+'\',[StringComparison]::OrdinalIgnoreCase)});foreach($p in $owned|Sort-Object @{Expression={if($_.Name-eq'AdvancedAINetworkLauncher.exe'){0}else{1}}}){Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue};Remove-ItemProperty $run -Name AdvancedAIPrivateNetwork}}
if($service){Stop-Service $name -ErrorAction Stop;Set-Service $name -StartupType Disabled}
$observerRoot=Join-Path $root 'observer'
$task=Get-ScheduledTask -TaskPath '\' -TaskName 'AdvancedAINetworkProtectionObserver' -ErrorAction SilentlyContinue
if($task -and $task.Actions.Count -eq 1 -and $task.Actions[0].Execute.StartsWith($observerRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
    Stop-ScheduledTask -InputObject $task
    Unregister-ScheduledTask -InputObject $task -Confirm:$false
}
$shell=New-Object -ComObject WScript.Shell
try{
    foreach($shortcut in '高级 AI - 检查出口.lnk','高级 AI - 紧急暂停联网.lnk'){
        $file=Join-Path ([Environment]::GetFolderPath('Desktop')) $shortcut
        if((Test-Path -LiteralPath $file) -and $shell.CreateShortcut($file).TargetPath.StartsWith($observerRoot+'\',[StringComparison]::OrdinalIgnoreCase)){Remove-Item -LiteralPath $file}
    }
}finally{[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)|Out-Null}
if($RestoreNetwork){
    & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Guard\Guard-Setup.ps1') -Action Disable
    if($LASTEXITCODE-ne 0){throw '保护解除未完成，请保留安装包并检查 Guard 状态。'}
    & (Join-Path $PSScriptRoot 'Tools\GuardPolicyTool.exe') remove-owned-guard
    if($LASTEXITCODE-ne 0){throw '解除本程序持久阻断失败。请保留安装包并重试。'}
    $policy=New-Object -ComObject HNetCfg.FwPolicy2;try{$names=@($policy.Rules|Where-Object {$_.Grouping-eq$name}|ForEach-Object {$_.Name});foreach($rule in $names){$policy.Rules.Remove($rule)}}finally{[Runtime.InteropServices.Marshal]::ReleaseComObject($policy)|Out-Null}
    Write-Output '本程序后台与域名保护已停用。配置与程序文件保留以便恢复；未卸载可能被其他软件使用的 WinDivert 或 Npcap。'
}else{Write-Output '转发后台与自启动已停用，域名、受保护程序和 IPv4 网段的阻断仍然保留。若要恢复原网络，请先恢复 Clash 原脚本，再运行 Uninstall.ps1 -RestoreNetwork。'}
