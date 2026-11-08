param([Parameter(Mandatory=$true)][string]$ExpectedGateway)
$package=Split-Path -Parent $PSScriptRoot
. (Join-Path $package 'compatibility\Runtime.ps1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$appRoot=Join-Path $env:ProgramData 'AdvancedAINetworkLanGateway\observer'
$data=Join-Path $env:LOCALAPPDATA 'AdvancedAINetworkProtection'
$exe='ProtectionObserver.exe'
$hash=(Get-FileHash -LiteralPath (Join-Path $package ('Tools\'+$exe))).Hash
$dest=Join-Path $appRoot $hash.Substring(0,16)
$program=Join-Path $dest $exe
$desktop=[Environment]::GetFolderPath('Desktop')
$taskName='AdvancedAINetworkProtectionObserver'
function Put-File($source,$target){
    $wanted=(Get-FileHash -LiteralPath $source).Hash
    if(!(Test-Path -LiteralPath $target)){Copy-Item -LiteralPath $source -Destination $target}
    if((Get-FileHash -LiteralPath $target).Hash-ne$wanted){throw ('Installed file hash mismatch: '+$target)}
}
$null=New-Item -ItemType Directory -Path (Join-Path $dest 'probe') -Force
Put-File (Join-Path $package ('Tools\'+$exe)) $program
Put-File (Join-Path $package 'Tools\NetworkProbe.exe') (Join-Path (Join-Path $dest 'probe') (Get-AiCompatibility 'S_11b496da7187c8'))
Put-File (Join-Path $package 'App\resources\native\AdvancedAINetworkAgent.exe') (Join-Path $dest 'AdvancedAINetworkAgent.exe')
$shell=New-Object -ComObject WScript.Shell
try{
    foreach($item in @(@('高级 AI - 检查出口','--check',23),@('高级 AI - 紧急暂停联网','--pause',131))){
        $linkFile=Join-Path $desktop ($item[0]+'.lnk')
        $link=$shell.CreateShortcut($linkFile)
        if((Test-Path -LiteralPath $linkFile)-and!$link.TargetPath.StartsWith($appRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'An unrelated shortcut already uses this name.'}
        $link.TargetPath=$program;$link.Arguments=$item[1];$link.WorkingDirectory=$dest
        $link.IconLocation=(Join-Path $env:WINDIR 'System32\shell32.dll')+','+$item[2]
        $link.Save()
        $check=$shell.CreateShortcut($linkFile)
        if($check.TargetPath-ne$program-or$check.Arguments-ne$item[1]){throw 'Shortcut verification failed.'}
    }
}finally{[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)|Out-Null}
$old=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
if($old -and !$old.Actions[0].Execute.StartsWith($appRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected existing task.'}
$action=New-ScheduledTaskAction -Execute $program -Argument '--watch' -WorkingDirectory $dest
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal=New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 5 -RestartInterval ([TimeSpan]::FromMinutes(1))
if($old -and $old.Actions[0].Execute -ne $program -and $old.State -eq 'Running'){
    $retiring=@(Get-Process ProtectionObserver -ErrorAction SilentlyContinue|Where-Object {$_.Path -eq $old.Actions[0].Execute})
    Stop-ScheduledTask -InputObject $old
    foreach($process in $retiring){if(!$process.WaitForExit(8000)){throw 'The previous observer has not exited.'}}
}
$null=Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description '登录后独立监测高级 AI 的网关状态和公网出口，异常时在托盘提醒。' -Force
Start-ScheduledTask -TaskName $taskName -TaskPath '\'
$deadline=[datetime]::UtcNow.AddSeconds(25)
$record=Join-Path $data 'observer.json'
do{
    Start-Sleep -Milliseconds 400
    try{
        $r=Get-Content -LiteralPath $record -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json
        $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\'
        if($task.State -eq 'Ready' -and !@(Get-Process ProtectionObserver -ErrorAction SilentlyContinue|Where-Object Path -eq $program).Count){
            Start-ScheduledTask -InputObject $task
        }
        $process=Get-Process -Id $r.pid -ErrorAction Stop
        if($task.State -eq 'Running' -and $process.Path -eq $program -and $process.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId -and
           $r.state -eq 'ready' -and $r.gateway -eq $ExpectedGateway -and $r.last_check_utc -and (([datetime]::UtcNow)-[datetime]::Parse($r.last_check_utc).ToUniversalTime()).TotalSeconds -lt 30){
            [pscustomobject]@{installed=$true;task=$task.State.ToString();privilege=$task.Principal.RunLevel.ToString();pid=$r.pid;gateway=$r.gateway;egress=$r.ip;checked_utc=$r.last_check_utc;desktop=$desktop;folder=$dest;data=$data}|ConvertTo-Json;return
        }
    }catch{}
}while([datetime]::UtcNow -lt $deadline)
throw 'Observer setup requires attention: a fresh heartbeat and HTTPS check from the logged-in session were not verified.'
