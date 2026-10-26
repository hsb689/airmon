# setup_codesign.ps1 -- 一次性安装本机代码签名证书
#
# 做的事:
#   1. 把 certs\airmon_codesign.pfx 导入"当前用户\个人"证书库(带私钥)
#   2. 把 certs\airmon_codesign.cer 装进"受信任的根证书颁发机构"
#   3. 再把同一个 .cer 装进"受信任的发布者"
#   4. 给 build\airmon.exe 签名
#
# 只影响当前 Windows 用户, 不需要管理员权限, 不改系统级设置.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$pfx  = Join-Path $root 'certs\airmon_codesign.pfx'
$cer  = Join-Path $root 'certs\airmon_codesign.cer'
$exe  = Join-Path $root 'build\airmon.exe'
$pwd  = 'AirMon-Local-Sign-2026'

Write-Host '============================================' -ForegroundColor Cyan
Write-Host ' 安装 AirMon 本机签名证书' -ForegroundColor Cyan
Write-Host '============================================' -ForegroundColor Cyan

if (-not (Test-Path $pfx)) { Write-Host "找不到 $pfx" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $cer)) { Write-Host "找不到 $cer" -ForegroundColor Red; exit 1 }

# 1. 导入带私钥的证书
try {
    $c = Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\CurrentUser\My `
         -Password (ConvertTo-SecureString -String $pwd -AsPlainText -Force)
    Write-Host "[1/4] 已导入证书到 当前用户\个人" -ForegroundColor Green
    Write-Host "      Subject: $($c.Subject)"
    Write-Host "      指纹   : $($c.Thumbprint)"
} catch {
    Write-Host "[1/4] 导入失败: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "      如果提示已存在, 可以忽略并继续." -ForegroundColor Yellow
}

# 2. 装进受信任的根
& certutil -addstore -user Root $cer 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host '[2/4] 已装进 受信任的根证书颁发机构' -ForegroundColor Green
} else {
    Write-Host "[2/4] 装入受信任根失败(退出码 $LASTEXITCODE).可能出现过一个确认对话框, 需要点『是』." -ForegroundColor Yellow
}

# 3. 装进受信任的发布者
& certutil -addstore -user TrustedPublisher $cer 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host '[3/4] 已装进 受信任的发布者' -ForegroundColor Green
} else {
    Write-Host "[3/4] 装入受信任发布者失败(退出码 $LASTEXITCODE)." -ForegroundColor Yellow
}

# 4. 签名现有 exe
& (Join-Path $root 'codesign.ps1')

Write-Host ''
Write-Host '完成.以后 build.bat 编译完会自动签名.' -ForegroundColor Cyan
