#Requires -Version 7
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
$version = 'cpython-3.12.13-windows-x86_64-none'
& uv python install $version
if ($LASTEXITCODE) { throw 'Cannot install the shared-radio build interpreter' }
$python = (& uv python find $version).Trim()
if ($LASTEXITCODE) { throw 'Cannot locate the shared-radio build interpreter' }
$base = Split-Path $python
$worker = Join-Path $Destination 'shared-radio'
$runtime = Join-Path $worker 'runtime'
$lib = Join-Path $runtime 'Lib'
New-Item -ItemType Directory -Force $lib | Out-Null
foreach ($name in 'worker.py','broker.py','usb_radio.py','discovery.py') {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) $worker
}
foreach ($name in 'python.exe','LICENSE.txt','DLLs') {
    Copy-Item -LiteralPath (Join-Path $base $name) $runtime -Recurse -Force
}
Copy-Item "$base\*.dll" $runtime
Get-ChildItem "$base\Lib" -Exclude 'site-packages','__pycache__','test','ensurepip','idlelib','tkinter','turtledemo' |
    Copy-Item -Destination $lib -Recurse -Force
& uv pip install --python $python --target "$lib\site-packages" --link-mode copy --no-deps -r "$PSScriptRoot\requirements.txt"
if ($LASTEXITCODE) { throw 'Cannot package shared-radio dependencies' }
# Isolate imports from the current directory, user site and environment.
@('Lib','DLLs','.','Lib\site-packages','..') | Set-Content -Encoding ascii "$runtime\python312._pth"
& "$runtime\python.exe" -B -c 'import worker'
if ($LASTEXITCODE) { throw 'Packaged shared-radio runtime failed its import check' }
