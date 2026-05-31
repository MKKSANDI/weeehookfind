$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

cargo build --release --manifest-path ".\src\weehok-scanner\Cargo.toml"
dotnet build ".\Weehok.sln" -c Release

Write-Host "Built Weehok:"
Write-Host "  .\src\Weehok.App\bin\Release\net9.0-windows\Weehok.exe"
