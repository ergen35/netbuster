# Fabrique les paquets Windows dans dist\ : l'archive portable (.zip) et l'installateur (setup.exe).
# Demande Rust avec les outils de compilation de Visual Studio, et Inno Setup pour l'installateur.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"$' | Select-Object -First 1).Matches[0].Groups[1].Value
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path dist | Out-Null
$name = "netbuster-$version-windows-x64"
$folder = Join-Path dist $name
if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
New-Item -ItemType Directory -Path $folder | Out-Null
Copy-Item target\release\netbuster.exe $folder
Copy-Item LICENSE $folder
Compress-Archive -Force -Path $folder -DestinationPath "dist\$name.zip"
Remove-Item -Recurse -Force $folder

$iscc = Get-Command iscc -ErrorAction SilentlyContinue
$path = if ($iscc) { $iscc.Source } else { "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" }
if (-not (Test-Path $path)) {
    Write-Host "Inno Setup est absent : seule l'archive .zip a été fabriquée."
    exit 0
}
& $path "/DAppVersion=$version" packaging\windows\netbuster.iss
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Get-ChildItem dist
