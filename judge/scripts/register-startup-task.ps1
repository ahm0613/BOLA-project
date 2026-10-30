# 작업 스케줄러에 "BOLA 자동 시작" 등록 (관리자 PowerShell에서 한 번 실행)
#   이 계정으로 로그온하면 30초 뒤 bola-startup.ps1을 가장 높은 권한으로 실행 (포트 전달에 관리자 권한 필요)
#   WSL은 사용자별로 동작해서, 로그인 전(부팅 직후)에는 실행할 수 없음
#   지우려면: Unregister-ScheduledTask -TaskName "BOLA 자동 시작" -Confirm:$false
$ErrorActionPreference = "Stop"
$name = "BOLA 자동 시작"
$script = Join-Path $PSScriptRoot "bola-startup.ps1"
$user = "$env:USERDOMAIN\$env:USERNAME"

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$trigger.Delay = "PT30S"                                # 로그온 직후 바로 말고 30초 뒤 (네트워크·WSL 준비 시간)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "WSL Docker의 bola 컨테이너(realtime, judge, postgres) 시작 + 포트 전달(5432, 5170). 로그: judge\output\startup.log" `
    -Force | Out-Null
$log = Join-Path $PSScriptRoot "..\output\register-task.log"
"등록됨: $name / 사용자 $user / 로그온 30초 뒤 / $script" | Out-File $log -Encoding utf8
Get-ScheduledTask -TaskName $name | Select-Object TaskName, State | Out-File $log -Append -Encoding utf8
