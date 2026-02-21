Write-Host "=== 1. Reset password for ku@gmail.com ==="
$body = '{"customer_email":"ku@gmail.com","new_password":"12345"}'
try {
    $r = Invoke-RestMethod -Uri 'http://localhost:3000/api/reset-password' -Method POST -ContentType 'application/json' -Body $body
    Write-Host "RESET OK:" $r.message
} catch {
    Write-Host "RESET FAILED:" $_.ErrorDetails.Message
}

Start-Sleep -Milliseconds 300

Write-Host ""
Write-Host "=== 2. Login with new password ==="
$loginBody = '{"customer_email":"ku@gmail.com","customer_password":"12345"}'
try {
    $r = Invoke-RestMethod -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $loginBody
    Write-Host "LOGIN OK! Name:" $r.customer_name "| Account:" $r.account_number
} catch {
    Write-Host "LOGIN FAILED:" $_.ErrorDetails.Message
}
