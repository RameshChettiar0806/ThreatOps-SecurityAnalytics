# ThreatOps SIEM - Local Development Startup Script
# This script activates the virtual environment and starts the Flask server

Write-Host "🛡️  ThreatOps SIEM - Starting Local Development Server..." -ForegroundColor Cyan
Write-Host ""

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Set Python path for module imports
$env:PYTHONPATH = (Get-Location).Path

# Check if MySQL is running (optional - won't stop execution)
Write-Host "Checking MySQL connection..." -ForegroundColor Yellow
try {
    # This is just informational
    Write-Host "Make sure MySQL is running on localhost:3306" -ForegroundColor Gray
} catch {
    Write-Host "Note: Ensure MySQL server is running" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🚀 Starting Flask server..." -ForegroundColor Green
Write-Host "📍 Server will be available at: http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host "🔐 Login with: rajesh_kumar / ADM123" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host "----------------------------------------" -ForegroundColor Gray
Write-Host ""

# Run the Flask application using venv Python
& ".\venv\Scripts\python.exe" "threatops\app.py"
