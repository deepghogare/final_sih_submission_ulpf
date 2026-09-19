try {
    $ppt = New-Object -ComObject PowerPoint.Application
    $pres = $ppt.Presentations.Open("g:\SIH2026\SIH2026_ULPF_Official_Presentation.pptx", 1, 0, 0)
    $pres.SaveAs("g:\SIH2026\SIH2026_ULPF_Official_Presentation.pdf", 32)
    $pres.Close()
    $ppt.Quit()
    Write-Host "Exported to PDF successfully!"
} catch {
    Write-Host "PowerPoint COM error: " $_.Exception.Message
}
