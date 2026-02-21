$loginResp = Invoke-RestMethod -Uri 'http://localhost:3000/api/login' -Method POST `
    -ContentType 'application/json' `
    -Body '{"customer_email":"arjun@kodbank.com","customer_password":"test@123"}'
$token = $loginResp.token

$aiResp = Invoke-RestMethod -Uri 'http://localhost:3000/api/ai-chat' -Method POST `
    -Headers @{ Authorization="Bearer $token"; "Content-Type"="application/json" } `
    -Body '{"message":"What is a savings account?","history":[]}'

Write-Host "AI REPLY:" $aiResp.reply
