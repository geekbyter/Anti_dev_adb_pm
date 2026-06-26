param(
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$moduleDir = (Resolve-Path (Join-Path $projectRoot "module")).Path

if (-not $Output) {
    $propPath = Join-Path $moduleDir "module.prop"
    $versionLine = Get-Content -LiteralPath $propPath | Where-Object { $_ -like "version=*" } | Select-Object -First 1
    $version = if ($versionLine) { $versionLine.Substring("version=".Length) } else { "v0.0.0" }
    $Output = "anti_dev_pm_zygisk-$version.zip"
}

$outPath = Join-Path $projectRoot $Output
$zygiskDir = Join-Path $moduleDir "zygisk"
New-Item -ItemType Directory -Force -Path $zygiskDir | Out-Null

$abiMap = [ordered]@{
    "arm64-v8a" = "arm64-v8a.so"
    "armeabi-v7a" = "armeabi-v7a.so"
    "x86" = "x86.so"
    "x86_64" = "x86_64.so"
}

foreach ($abi in $abiMap.Keys) {
    $built = Join-Path (Join-Path (Join-Path $projectRoot "libs") $abi) "libanti_dev_pm_zygisk.so"
    $dest = Join-Path $zygiskDir ($abiMap[$abi])
    if (-not (Test-Path -LiteralPath $built)) {
        throw "Missing built library for ${abi}: $built. Run ndk-build first."
    }
    Copy-Item -LiteralPath $built -Destination $dest -Force
}

if (Test-Path -LiteralPath $outPath) {
    Remove-Item -LiteralPath $outPath -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($outPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem -LiteralPath $moduleDir -Recurse -File -Force |
        Where-Object { $_.Name -notlike ".fuse_hidden*" -and $_.Name -notlike "*.tmp*" } |
        ForEach-Object {
            $rel = $_.FullName.Substring($moduleDir.Length).TrimStart("\", "/").Replace("\", "/")
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip,
                $_.FullName,
                $rel,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
}
finally {
    if ($zip) { $zip.Dispose() }
}

Write-Host "Wrote $outPath"

$zipRead = [System.IO.Compression.ZipFile]::OpenRead($outPath)
try {
    $zipRead.Entries |
        Sort-Object FullName |
        Select-Object FullName, Length |
        Format-Table -AutoSize
}
finally {
    $zipRead.Dispose()
}
