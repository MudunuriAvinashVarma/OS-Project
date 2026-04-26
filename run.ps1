Start-Process powershell -ArgumentList "-NoExit -Command cd $PSScriptRoot\backend; python app.py"
Start-Process powershell -ArgumentList "-NoExit -Command cd $PSScriptRoot\frontend; python -m http.server 5500"

# wait a bit for server to start
Start-Sleep -Seconds 3

# open browser
Start-Process "http://localhost:5500"