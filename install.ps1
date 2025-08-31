param(
  [string]$ProjectDir = "$PSScriptRoot",
  [string]$IdsScript  = "$PSScriptRoot\main.py",
  [switch]$AutoStart,
  [string]$OpenAIKey = ""
)

$ErrorActionPreference = "Stop"

function Write-Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host "[ERR ] $m" -ForegroundColor Red }
function Test-Cmd { param([string]$Name) try { $null = Get-Command $Name -ErrorAction Stop; $true } catch { $false } }
function Add-ToPathIfExists { param([string]$p) if(Test-Path $p){ if(-not ($env:Path -split ';' | Where-Object { $_ -eq $p })){ $env:Path = "$p;$env:Path"; Write-Info "Added to PATH: $p" } } }
function Run-CmdBatch { param([string[]]$Lines,[string]$WorkDir)
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("oqsbuild_" + [IO.Path]::GetRandomFileName() + ".cmd")
  Set-Content -Path $tmp -Value (@("@echo off","setlocal") + $Lines + @("endlocal")) -Encoding ASCII
  try {
    if($WorkDir){ Push-Location $WorkDir }
    & cmd.exe /c "`"$tmp`""
    if($LASTEXITCODE -ne 0){ throw "Command batch failed with exit code $LASTEXITCODE" }
  } finally {
    if($WorkDir){ Pop-Location }
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

#----- OS check
$IsWindowsCompat = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
if (-not $IsWindowsCompat) { Write-Err "Windows-only script."; exit 1 }

#----- Project dir
if(-not (Test-Path $ProjectDir)) { New-Item -ItemType Directory -Path $ProjectDir | Out-Null }
Set-Location $ProjectDir

#----- Ensure base tools (winget path installs)
$haveWinget = Test-Cmd -Name "winget"
if($haveWinget){
  Write-Info "Ensuring base tools via winget"
  $pkgs = @(
    @{Id="Git.Git"; Name="Git" },
    @{Id="Kitware.CMake"; Name="CMake" },
    @{Id="Ninja-build.Ninja"; Name="Ninja" },
    @{Id="Python.Python.3.11"; Name="Python" },
    @{Id="Microsoft.VisualStudio.2022.BuildTools"; Name="VS Build Tools"; Override='--quiet --wait --norestart --nocache --installPath "C:\BuildTools" --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.VC.CMake.Project --add Microsoft.VisualStudio.Component.Windows11SDK.22621' }
  )
  foreach($p in $pkgs){
    $installed = $false
    try { $out = winget list --id $($p.Id) -e 2>$null; if($LASTEXITCODE -eq 0 -and $out){ $installed = $true } } catch {}
    if(-not $installed){
      Write-Info "Installing $($p.Name)"
      $args = @("--id",$p.Id,"-e","--accept-source-agreements","--accept-package-agreements")
      if($p.Override){ $args += @("--override",$p.Override) }
      try { winget install @args } catch { Write-Warn "winget install failed for $($p.Id). Install manually if needed." }
    } else {
      Write-Info "$($p.Name) already installed"
    }
  }
} else {
  Write-Warn "winget not found; skipping automatic installs"
}

#----- Tool paths (session PATH only)
Add-ToPathIfExists "C:\Program Files\CMake\bin"
Add-ToPathIfExists "C:\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
# try common VS compiler bin too (not strictly required if we call vcvars)
$vsHostBin = Get-ChildItem "C:\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64" -Directory -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if($vsHostBin){ Add-ToPathIfExists $vsHostBin.FullName }

#----- Locate vcvars batch (we installed VS Build Tools to C:\BuildTools)
$VcVars = @(
  "C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
  "C:\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

#----- Python/venv
$pyExe = $null
if(Test-Cmd -Name "py"){ try { $pyExe = (& py -3.11 -c "import sys;print(sys.executable)") } catch {} }
if(-not $pyExe){ if(Test-Cmd -Name "python"){ try { $pyExe = (& python -c "import sys;print(sys.executable)") } catch {} } }
if(-not $pyExe){ Write-Err "Python not available. Install Python 3.11 and re-run."; exit 1 }

$venvPath = Join-Path $ProjectDir ".venv"
$venvPy   = Join-Path $venvPath "Scripts\python.exe"
$venvPip  = Join-Path $venvPath "Scripts\pip.exe"

if(-not (Test-Path $venvPy)){
  Write-Info "Creating venv at $venvPath"
  & $pyExe -m venv $venvPath
} else {
  Write-Info "Using existing venv at $venvPath"
}

Write-Info "Upgrading pip/setuptools/wheel"
& $venvPy -m pip install --upgrade pip setuptools wheel

Write-Info "Installing core deps"
& $venvPip install --upgrade psutil httpx[http2] bleach jsonschema cryptography

# Note: correct PyPI package is liboqs-python; import name is 'oqs'
Write-Info "Installing liboqs-python (Python wrapper)"
$oqsOk = $false
try { & $venvPip install --upgrade liboqs-python -v } catch {}

function Test-OQS {
  try {
    $out = & $venvPy -c 'import oqs; print(",".join(oqs.get_enabled_kem_mechanisms()[:3]))' 2>$null
    if($LASTEXITCODE -eq 0 -and $out){ return $true }
  } catch {}
  return $false
}

$oqsOk = Test-OQS

# If import fails, try to trigger liboqs auto-build via oqs on Windows (needs vcvars + cmake + ninja)
if(-not $oqsOk -and $VcVars){
  Write-Warn "oqs import failed; attempting auto-build via liboqs-python"
  $lines = @(
    "call `"$VcVars`"",
    "`"$venvPy`" -c `"import oqs; print(oqs.get_enabled_kem_mechanisms()[:3])`""
  )
  try { Run-CmdBatch -Lines $lines } catch { Write-Warn $_.Exception.Message }
  $oqsOk = Test-OQS
}

# If still failing, build liboqs (C library) ourselves with Ninja and copy oqs.dll into site-packages\oqs\
if(-not $oqsOk){
  Write-Warn "Auto-build failed; building liboqs (C) from source with Ninja"
  $liboqsDir = Join-Path $ProjectDir "liboqs"
  if(Test-Path $liboqsDir){ Remove-Item -Recurse -Force $liboqsDir }
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs $liboqsDir | Out-Null
  $buildDir = Join-Path $liboqsDir "build"
  New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

  if(-not $VcVars){ Write-Err "VS Build Tools vcvars script not found under C:\BuildTools. Cannot build liboqs."; exit 1 }

  $cmakeGen = 'cmake -G "Ninja" -DOQS_BUILD_SHARED=ON -DOQS_DIST_BUILD=ON ..'
  $ninjaCmd = 'ninja'
  $lines = @(
    "call `"$VcVars`"",
    $cmakeGen,
    "if errorlevel 1 exit /b 1",
    $ninjaCmd
  )

  try {
    Run-CmdBatch -Lines $lines -WorkDir $buildDir
  } catch {
    Write-Err "liboqs build failed: $($_.Exception.Message)"
    exit 1
  }

  $dllPath = Join-Path $buildDir "bin\oqs.dll"
  if(-not (Test-Path $dllPath)){
    Write-Err "oqs.dll not found after build at $dllPath"
    exit 1
  }

  $site = & $venvPy -c "import site,sys; print(site.getsitepackages()[0])"
  $oqsPkgDir = Join-Path $site "oqs"
  if(-not (Test-Path $oqsPkgDir)){ New-Item -ItemType Directory -Force -Path $oqsPkgDir | Out-Null }
  Copy-Item -Force $dllPath (Join-Path $oqsPkgDir "oqs.dll")
  Write-Info "Copied oqs.dll to $oqsPkgDir"

  # re-test import
  $oqsOk = Test-OQS
}

if(-not $oqsOk){
  Write-Err "Unable to import 'oqs'. Ensure CMake/Ninja/VS Build Tools are present. If you already built oqs.dll, place it in $((Join-Path $ProjectDir ".venv\Lib\site-packages\oqs")) and retry."
  exit 1
}

# Optional: constrain scrypt memory (OpenSSL) via env var used by your code if you add support for it
# $env:HYPERTIME_SCRYPT_MAXMEM = "134217728"  # 128MB (only if your code reads this)

#----- IDS script presence
if(-not (Test-Path $IdsScript)){
  Write-Err "IDS script not found at: $IdsScript"
  exit 1
}

#----- Provide OpenAI key to environment if passed
if($OpenAIKey){ $env:OPENAI_API_KEY = $OpenAIKey }

Write-Info "Setup complete"
Write-Host ""
Write-Host "Activate venv (optional):" -ForegroundColor Green
Write-Host " `"$venvPath\Scripts\Activate.ps1`""
Write-Host ""
Write-Host "Run IDS:" -ForegroundColor Green
Write-Host " `"$venvPy`" `"$IdsScript`""
if($AutoStart){
  Write-Info "Starting IDS now..."
  & $venvPy $IdsScript
}
