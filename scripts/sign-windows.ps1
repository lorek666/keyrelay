# M14-S5：Windows NSIS 产物签名占位脚本（B-55）。
#
# 用法：
#   pwsh scripts/sign-windows.ps1 [-Installer <path>]
#
# 环境变量：
#   SIGNING_CERT     PFX 证书路径
#   SIGNING_PASSWORD PFX 密码
#
# 退出码：
#   0  已签名，或证书缺失但已打印警告跳过（不阻塞 CI）
#   3  signtool 调用失败（已配置证书却签不上）
#   4  脚本自身错误（找不到 installer）
#
# 本脚本不本机真签（本机是 macOS，无 Windows 证书）；真签在 ci-windows.yml 的 sign-nsis
# step 上跑（secrets.SIGNING_CERT 配置后）。见 内部文档库 docs/specs/M14-S5-Windows-CI.md §4.3。

param(
    [string]$Installer = ""
)

$ErrorActionPreference = "Stop"

# 无证书：打印 SKIP 警告，退出 0（不阻塞 CI）
if (-not $env:SIGNING_CERT) {
    Write-Host "SKIP: 未配置 SIGNING_CERT，产物未签名（Windows SmartScreen 会警告）"
    exit 0
}

# 定位 installer：未指定 -Installer 时在 NSIS bundle 目录下找首个 *.exe
if (-not $Installer) {
    $nsisDir = "src-tauri\target\x86_64-pc-windows-msvc\release\bundle\nsis"
    if (-not (Test-Path $nsisDir)) {
        Write-Error "找不到 NSIS bundle 目录: $nsisDir（先跑 pnpm tauri build --target x86_64-pc-windows-msvc）"
        exit 4
    }
    $candidates = Get-ChildItem -Path $nsisDir -Filter "*.exe" -ErrorAction SilentlyContinue
    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Error "NSIS 目录下无 *.exe: $nsisDir"
        exit 4
    }
    $Installer = $candidates[0].FullName
}

if (-not (Test-Path $Installer)) {
    Write-Error "installer 不存在: $Installer"
    exit 4
}

# signtool 重试 2 次（时间戳服务偶发超时）
$maxRetries = 2
$attempt = 0
while ($attempt -le $maxRetries) {
    $attempt++
    # 假设 signtool 在 PATH（Windows runner 的 Windows SDK 通常已加）；若不在，
    # YG 真签时把 signtool 改为绝对路径（如 C:\Program Files (x86)\Windows Kits\10\bin\...\x64\signtool.exe）
    & signtool sign /fd SHA256 /f $env:SIGNING_CERT /p $env:SIGNING_PASSWORD $Installer
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SIGNED: $Installer"
        exit 0
    }
    if ($attempt -le $maxRetries) {
        Write-Warning "signtool 失败（attempt $attempt），5s 后重试"
        Start-Sleep -Seconds 5
    }
}

Write-Error "signtool 失败（重试 $maxRetries 次后仍失败，exit $LASTEXITCODE）"
exit 3
