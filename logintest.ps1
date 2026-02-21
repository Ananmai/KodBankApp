$body = '{"customer_email":"ku@gmail.com","customer_password":"12345"}'
try {
    $r = Invoke-RestMethod -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $body
    Write-Host "LOGIN OK:" $r.customer_name $r.token.Substring(0,30)
} catch {
    $code = $_.Exception.Response.StatusCode.Value__
    $msg  = $_.ErrorDetails.Message
    Write-Host "LOGIN FAILED (HTTP $code):" $msg
}
