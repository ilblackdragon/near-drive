# NEAR Drive installer for Windows (PowerShell 5.1+).
#
#   irm https://github.com/ilblackdragon/near-drive/releases/latest/download/install.ps1 | iex
#
# Installs near-drive.exe, near-drive-gateway.exe and near-drive-tray.exe from
# the latest GitHub release into %LOCALAPPDATA%\NEAR Drive\bin (override with
# NEAR_DRIVE_INSTALL_DIR), checks the archive against SHA256SUMS, and adds the
# folder to your user PATH. NEAR_DRIVE_VERSION=v0.1.0 pins a version.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = 'ilblackdragon/near-drive'
$version = if ($env:NEAR_DRIVE_VERSION) { $env:NEAR_DRIVE_VERSION } else { 'latest' }
$dir = if ($env:NEAR_DRIVE_INSTALL_DIR) { $env:NEAR_DRIVE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'NEAR Drive\bin' }

# x64 build; Windows on Arm runs it through emulation.
$target = 'x86_64-pc-windows-msvc'
$asset = "near-drive-$target.zip"
$base = if ($env:NEAR_DRIVE_DOWNLOAD_BASE) { $env:NEAR_DRIVE_DOWNLOAD_BASE } elseif ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("near-drive-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading NEAR Drive ($version, $target)..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

    $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { $_ -match " $([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "$asset is not listed in SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $asset (expected $expected, got $actual)" }

    Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($b in 'near-drive', 'near-drive-gateway', 'near-drive-tray') {
        $src = Join-Path $tmp "near-drive-$target\$b.exe"
        if (Test-Path $src) {
            $dst = Join-Path $dir "$b.exe"
            # A running copy can't be overwritten but can be renamed out of the way.
            if (Test-Path $dst) { Move-Item -Force $dst "$dst.old" -ErrorAction SilentlyContinue }
            Copy-Item -Force $src $dst
            Remove-Item -Force "$dst.old" -ErrorAction SilentlyContinue
        }
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $dir)) {
    [Environment]::SetEnvironmentVariable('Path', ($(if ($userPath) { "$userPath;" } else { '' }) + $dir), 'User')
    $env:Path = "$env:Path;$dir"
    Write-Host "Added $dir to your PATH (new terminals pick it up)."
}

$v = & (Join-Path $dir 'near-drive.exe') --version
Write-Host "Installed $v to $dir"
if (-not (Get-Command near -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "NEAR Drive uses near-cli-rs for your NEAR keys; install it with:"
    Write-Host "  irm https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.ps1 | iex"
}
Write-Host ""
Write-Host "Get started: near drive login"
