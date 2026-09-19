# Stop the Wazuh SIEM stack
Write-Host "[+] Stopping Wazuh SIEM stack..." -ForegroundColor Yellow
Set-Location -Path "$PSScriptRoot\..\wazuh-docker\single-node"
docker compose down
Set-Location -Path "$PSScriptRoot\.."
Write-Host "[✓] Wazuh SIEM stack stopped." -ForegroundColor Green
