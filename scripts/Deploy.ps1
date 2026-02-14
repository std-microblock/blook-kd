$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Connecting to VM: $VMName" -ForegroundColor Green

# Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true
Copy-VMFile -VMName $VMName -SourcePath ".\build\windows\x64\releasedbg\cli-new.exe" -DestinationPath "C:\" -FileSource Host -Force

Write-Host ">>> Starting Cli..." -ForegroundColor Yellow
Invoke-Command -VMName $VMName -ScriptBlock {
    C:\cli-new.exe --test -d asrock
} -Credential $Cred 
