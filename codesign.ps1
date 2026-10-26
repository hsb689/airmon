# codesign.ps1 -- 给 build\airmon.exe 签名
#
# 证书从"当前用户\个人"里按 Subject 找(需要先运行一次 setup_codesign.ps1).
# 找不到证书就跳过, 不报错 -- 这样没装证书的机器上 build.bat 也能正常编译.

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe  = Join-Path $root 'build\airmon.exe'

if (-not (Test-Path $exe)) { Write-Host 'sign: 找不到 build\airmon.exe, 跳过'; exit 0 }

$cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like 'CN=AirMon Desktop Air Monitor*' -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

if (-not $cert) {
    Write-Host 'sign: 本机未安装签名证书, 跳过(运行 setup_codesign.bat 可安装)' -ForegroundColor Yellow
    exit 0
}

try {
    $r = Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop
    if ($r.Status -eq 'Valid') {
        Write-Host "sign: 已签名 ($($cert.Subject))" -ForegroundColor Green
    } else {
        Write-Host "sign: 签名结果 $($r.Status) - $($r.StatusMessage)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "sign: 签名失败 - $($_.Exception.Message)" -ForegroundColor Yellow
}
