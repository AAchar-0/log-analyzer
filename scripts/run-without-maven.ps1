# Compiles and runs the log analyzer with ONLY the JDK (no Maven needed).
# Usage, from the project folder, in the VS Code terminal (PowerShell):
#   .\scripts\run-without-maven.ps1 generate --lines 1000000 --out sample.log
#   .\scripts\run-without-maven.ps1 analyze --file sample.log --strategy all
#   .\scripts\run-without-maven.ps1 serve
# Tests are not run by this script; run them with Maven or the VS Code Testing panel.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "out"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Path $out | Out-Null
$sources = Get-ChildItem -Path (Join-Path $root "src\main\java") -Recurse -Filter *.java | ForEach-Object { $_.FullName }
javac --release 21 -d $out $sources
if ($LASTEXITCODE -ne 0) { throw "Compilation failed" }
Copy-Item -Recurse (Join-Path $root "src\main\resources\static") (Join-Path $out "static")
java -cp $out io.github.aachar0.loganalyzer.Main @args
