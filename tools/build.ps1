param(
    [string]$NdkBuild = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $NdkBuild) {
    $candidates = @()
    if ($env:ANDROID_NDK_HOME) { $candidates += (Join-Path $env:ANDROID_NDK_HOME "ndk-build.cmd") }
    if ($env:ANDROID_NDK_HOME) { $candidates += (Join-Path $env:ANDROID_NDK_HOME "ndk-build") }
    if ($env:ANDROID_NDK_ROOT) { $candidates += (Join-Path $env:ANDROID_NDK_ROOT "ndk-build.cmd") }
    if ($env:ANDROID_NDK_ROOT) { $candidates += (Join-Path $env:ANDROID_NDK_ROOT "ndk-build") }
    if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk\29.0.14206865\ndk-build.cmd") }
    if ($env:ANDROID_HOME) { $candidates += (Join-Path $env:ANDROID_HOME "ndk/29.0.14206865/ndk-build") }
    if ($env:ANDROID_SDK_ROOT) { $candidates += (Join-Path $env:ANDROID_SDK_ROOT "ndk/29.0.14206865/ndk-build") }

    $NdkBuild = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not $NdkBuild) {
    throw "ndk-build not found. Set ANDROID_NDK_HOME or pass -NdkBuild."
}

& $NdkBuild -C (Join-Path $projectRoot "jni")
if ($LASTEXITCODE -ne 0) {
    throw "ndk-build failed with exit code $LASTEXITCODE"
}

& (Join-Path $projectRoot "tools/package.ps1")
