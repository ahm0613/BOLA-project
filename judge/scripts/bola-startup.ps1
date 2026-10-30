# 로그온할 때 자동 실행 (작업 스케줄러 "BOLA 자동 시작"): WSL Docker의 bola 컨테이너 시작 + 포트 전달
#   ① 네트워크(LAN IP)가 잡힐 때까지 기다림
#   ② WSL을 깨우고 Docker가 준비될 때까지 기다린 뒤 docker compose up -d (stop으로 멈춘 컨테이너도 다시 켬)
#   ③ 바뀐 WSL IP로 포트 전달 다시 등록: 5432(DB, pc3만), 5170(로그 수신, 같은 LAN)
# 결과는 output/startup.log. 직접 실행하려면 관리자 PowerShell에서:
#   powershell -ExecutionPolicy Bypass -File D:\python-rule\judge\scripts\bola-startup.ps1
$ErrorActionPreference = "Continue"
$root = "/mnt/d/python-rule"                            # WSL에서 본 저장소 위치
$portproxy = Join-Path $PSScriptRoot "wsl-portproxy.ps1"
$log = Join-Path $PSScriptRoot "..\output\startup.log"
New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null

function Log($msg) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Add-Content -Path $log -Value $line -Encoding UTF8
}

Log "===== 시작 ====="

# ① 네트워크 대기 (최대 2분)
$deadline = (Get-Date).AddMinutes(2)
do {
    $lan = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
           Select-Object -First 1
    if ($lan) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if (-not $lan) { Log "실패: 네트워크(기본 게이트웨이)가 2분 안에 잡히지 않음"; exit 1 }
Log "LAN IP: $($lan.IPv4Address.IPAddress)"

# ② WSL Docker 준비 대기 (최대 3분) 후 컨테이너 시작
$deadline = (Get-Date).AddMinutes(3)
do {
    wsl -e docker info --format "{{.ServerVersion}}" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if ($LASTEXITCODE -ne 0) { Log "실패: WSL Docker가 3분 안에 준비되지 않음"; exit 1 }

$up = wsl -e sh -c "cd $root && docker compose up -d 2>&1"
Log ("docker compose up -d: " + (($up | Select-Object -Last 3) -join " | "))
$ps = wsl -e sh -c "cd $root && docker compose ps --format '{{.Name}}={{.Status}}'"
Log ("컨테이너: " + ($ps -join ", "))

# ③ 포트 전달 (WSL IP가 바뀌었으므로 다시 등록). 결과는 wsl-portproxy.ps1이 출력하는 "완료"/"실패: …"로 판단
function PortProxy($label, $params) {
    $out = (& $portproxy @params 2>&1 | Out-String) -split "`r?`n"
    $result = if ($out -contains "완료") { "완료" } else { (($out | Where-Object { $_ -match "실패" }) -join " ") }
    Log "포트 전달 $label`: $(if ($result) { $result } else { '결과 불명 - output/portproxy.log 확인' })"
}
PortProxy "5432 (pc3 192.168.0.26만)" @{ Remote = "192.168.0.26" }
PortProxy "5170 (같은 LAN)" @{ Port = 5170; Name = "bola realtime" }

$rules = netsh interface portproxy show v4tov4 | Select-String "5432|5170" | ForEach-Object { ($_ -replace "\s+", " ").Trim() }
Log ("현재 포트 전달: " + ($rules -join " / "))
Log "===== 끝 ====="
