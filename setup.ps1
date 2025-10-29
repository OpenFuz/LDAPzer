# LDAPzer Setup Script for Windows
# Quick setup for testing environments

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  LDAPzer - LDAP Security Testing Tools" -ForegroundColor Cyan
Write-Host "  Setup Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "[1/5] Checking Python version..." -ForegroundColor Yellow

$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonVersion = (python --version 2>&1) -replace 'Python ', ''
    $pythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonVersion = (python3 --version 2>&1) -replace 'Python ', ''
    $pythonCmd = "python3"
} else {
    Write-Host "[✗] Python not found. Please install Python 3.7+" -ForegroundColor Red
    exit 1
}

Write-Host "[✓] Python $pythonVersion found" -ForegroundColor Green

# Check Python version is 3.7+
$versionParts = $pythonVersion.Split('.')
$majorVersion = [int]$versionParts[0]
$minorVersion = [int]$versionParts[1]

if ($majorVersion -lt 3 -or ($majorVersion -eq 3 -and $minorVersion -lt 7)) {
    Write-Host "[✗] Python 3.7+ required, found $pythonVersion" -ForegroundColor Red
    exit 1
}

# Check directory structure
Write-Host ""
Write-Host "[2/5] Checking directory structure..." -ForegroundColor Yellow

if (!(Test-Path "tools") -or !(Test-Path "TestingPlan")) {
    Write-Host "[✗] Not in LDAPzer root directory" -ForegroundColor Red
    Write-Host "Please run this script from the LDAPzer root directory" -ForegroundColor Red
    exit 1
}
Write-Host "[✓] Directory structure verified" -ForegroundColor Green

# Optional: Install Scapy
Write-Host ""
Write-Host "[3/5] Optional dependencies..." -ForegroundColor Yellow
$installScapy = Read-Host "Install Scapy for advanced features? (y/N)"

if ($installScapy -eq 'y' -or $installScapy -eq 'Y') {
    Write-Host "Installing Scapy..." -ForegroundColor Yellow

    if (Get-Command pip -ErrorAction SilentlyContinue) {
        pip install -r tools/requirements.txt
        Write-Host "[✓] Scapy installed" -ForegroundColor Green

        Write-Host ""
        Write-Host "[!] Windows Note: Scapy requires Npcap for packet capture" -ForegroundColor Yellow
        Write-Host "    Download from: https://npcap.com/" -ForegroundColor Yellow
        Write-Host "    Install with 'WinPcap API-compatible mode' enabled" -ForegroundColor Yellow
    } else {
        Write-Host "[⚠] pip not found, skipping Scapy installation" -ForegroundColor Yellow
        Write-Host "   Install manually: pip install scapy" -ForegroundColor Yellow
    }
} else {
    Write-Host "[⚠] Scapy not installed (optional)" -ForegroundColor Yellow
    Write-Host "   You can install later with: pip install -r tools/requirements.txt" -ForegroundColor Yellow
}

# Test basic functionality
Write-Host ""
Write-Host "[4/5] Testing basic functionality..." -ForegroundColor Yellow

Push-Location tools
$testResult = & $pythonCmd preflight_checks/baseline_test.py --help 2>&1
Pop-Location

if ($LASTEXITCODE -eq 0 -or $testResult -like "*usage*") {
    Write-Host "[✓] Tools are working" -ForegroundColor Green
} else {
    Write-Host "[✗] Tool test failed" -ForegroundColor Red
    exit 1
}

# Display next steps
Write-Host ""
Write-Host "[5/5] Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Next Steps" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Review the workflow:" -ForegroundColor White
Write-Host "   Get-Content tools\WORKFLOW.md" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Run preflight check:" -ForegroundColor White
Write-Host "   cd tools" -ForegroundColor Gray
Write-Host "   $pythonCmd preflight_checks\baseline_test.py <TARGET_IP>" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Run security tests:" -ForegroundColor White
Write-Host "   cd test_harness" -ForegroundColor Gray
Write-Host "   $pythonCmd test_runner.py <TARGET_IP> -o results.json" -ForegroundColor Gray
Write-Host ""
Write-Host "4. View results:" -ForegroundColor White
Write-Host "   $pythonCmd results_logger.py results.json" -ForegroundColor Gray
Write-Host ""
Write-Host "For detailed instructions, see:" -ForegroundColor White
Write-Host "  - tools\QUICKSTART.md" -ForegroundColor Gray
Write-Host "  - tools\WORKFLOW.md" -ForegroundColor Gray
Write-Host ""
Write-Host "Happy testing!" -ForegroundColor Green
Write-Host ""
