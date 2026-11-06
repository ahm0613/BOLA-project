# keys\public.pem 을 kong\kong.yml 의 __PUBLIC_KEY__ 자리에 들여쓰기 맞춰 넣습니다.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$yml = Join-Path $PSScriptRoot 'kong\kong.yml'
$pem = Join-Path $PSScriptRoot 'keys\public.pem'
$content = [IO.File]::ReadAllText($yml)

if ($content -notmatch '__PUBLIC_KEY__') {
  Write-Host 'kong.yml에 __PUBLIC_KEY__ 마커가 없습니다 (이미 키가 들어가 있음).'
  exit 0
}

$indent = ' ' * 10
$key = (Get-Content $pem | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $indent + $_.Trim() }) -join "`n"
$content = $content.Replace($indent + '__PUBLIC_KEY__', $key)

[IO.File]::WriteAllText($yml, $content, (New-Object Text.UTF8Encoding $false))
Write-Host 'kong.yml에 공개키를 넣었습니다.'
