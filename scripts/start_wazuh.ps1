# Start the Wazuh SIEM stack
Write-Host "[+] Launching Wazuh SIEM (Indexer, Manager, Dashboard)..." -ForegroundColor Cyan
Set-Location -Path "$PSScriptRoot\..\wazuh-docker\single-node"
docker compose up -d
Set-Location -Path "$PSScriptRoot\.."

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " Wazuh Open-Source SIEM Stack is starting up!" -ForegroundColor Green
Write-Host " Wazuh SOC Console: http://localhost:8443" -ForegroundColor Yellow
Write-Host " Username: admin" -ForegroundColor White
Write-Host " Password: SecretPassword" -ForegroundColor White
Write-Host " Note: Initialization takes ~60-90 seconds on first start." -ForegroundColor Gray
Write-Host "========================================================`n" -ForegroundColor Green
