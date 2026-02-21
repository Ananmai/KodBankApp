Write-Host "=== 1. Register ku@gmail.com ==="
$regBody = '{"customer_name":"Test User","customer_email":"ku@gmail.com","customer_password":"12345","bank_balance":"1000"}'
try {
    $r = Invoke-RestMethod -Uri 'http://localhost:3000/api/register' -Method POST -ContentType 'application/json' -Body $regBody
    Write-Host "REGISTER OK:" $r.message
} catch {
    $code = $_.Exception.Response.StatusCode.Value__
    $msg  = $_.ErrorDetails.Message
    Write-Host "REGISTER HTTP $code :" $msg
}

Start-Sleep -Milliseconds 500

Write-Host ""
Write-Host "=== 2. Login ku@gmail.com (pass: 12345) ==="
$loginBody = '{"customer_email":"ku@gmail.com","customer_password":"12345"}'
try {
    $r = Invoke-RestMethod -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $loginBody
    Write-Host "LOGIN OK:" $r.customer_name "token length:" $r.token.Length
} catch {
    $code = $_.Exception.Response.StatusCode.Value__
    $msg  = $_.ErrorDetails.Message
    Write-Host "LOGIN FAILED (HTTP $code):" $msg
}
