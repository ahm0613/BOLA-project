# pc3(Streamlit)가 pc1의 PostgreSQL(WSL Docker 안)에 접속할 수 있게 포트를 전달
#   pc3 → pc1 LAN IP:5432 ──portproxy──▶ WSL IP:5432 ──▶ judge-postgres 컨테이너
# WSL IP는 재부팅·wsl --shutdown 때마다 바뀌므로, 그때마다 관리자 PowerShell에서 다시 실행:
#   powershell -ExecutionPolicy Bypass -File D:\python-rule\judge\scripts\wsl-portproxy.ps1
# 방화벽은 같은 LAN(LocalSubnet)에서 오는 연결만 허용. pc3만 허용하려면 -Remote 192.168.0.X
# 다른 포트도 같은 방식: 탐지 엔진 로그 수신은 -Port 5170 -Name "bola realtime"
param(
    [int]$Port = 5432,
    [string]$Remote = "LocalSubnet",
    [string]$Name = "bola judge postgres"
)
$ErrorActionPreference = "Stop"
$log = Join-Path $PSScriptRoot "..\output\portproxy.log"
New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null
Start-Transcript -Path $log -Force | Out-Null
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "관리자 PowerShell에서 실행해야 합니다" }

    # WSL(eth0) IP와 pc1의 LAN IP (기본 게이트웨이가 있는 연결)
    $wslIp = (wsl -e sh -c 'ip -4 -o addr show eth0 | awk ''{print $4}'' | cut -d/ -f1').Trim()
    $lanIp = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
              Select-Object -First 1).IPv4Address.IPAddress
    if (-not $wslIp -or -not $lanIp) { throw "IP를 찾지 못함 (WSL: '$wslIp', LAN: '$lanIp')" }
    "WSL IP: $wslIp / pc1 LAN IP: $lanIp / 포트: $Port"

    # portproxy는 IP Helper 서비스가 있어야 동작
    Set-Service iphlpsvc -StartupType Automatic
    Start-Service iphlpsvc

    # 이전 설정을 지우고 새 WSL IP로 다시 등록 (LAN IP에만 열어서 127.0.0.1:5432의 WSL 자체 전달과 겹치지 않게)
    netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=$lanIp 2>$null | Out-Null
    netsh interface portproxy add v4tov4 listenport=$Port listenaddress=$lanIp connectport=$Port connectaddress=$wslIp

    $rule = "$Name $Port"
    if (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -DisplayName $rule -RemoteAddress $Remote -Enabled True
    } else {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort $Port `
            -RemoteAddress $Remote -Action Allow -Profile Any | Out-Null
    }
    "방화벽 규칙 '$rule' (허용: $Remote)"
    netsh interface portproxy show v4tov4
    "완료"
}
catch {
    "실패: $_"
}
finally {
    Stop-Transcript | Out-Null
}
