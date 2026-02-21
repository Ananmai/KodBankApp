$body = '{"customer_email":"arjun@kodbank.com","customer_password":"test@123"}'
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$lr = Invoke-WebRequest -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $body -WebSession $session
Write-Host "LOGIN STATUS:" $lr.StatusCode
Write-Host "COOKIE SENT:" ($null -ne $lr.Headers['Set-Cookie'])

$mr = Invoke-WebRequest -Uri 'http://localhost:3000/api/me' -Method GET -WebSession $session
Write-Host "WITH-COOKIE /api/me STATUS:" $mr.StatusCode
Write-Host $mr.Content

try {
    $mr2 = Invoke-WebRequest -Uri 'http://localhost:3000/api/me' -Method GET
    Write-Host "NO-COOKIE STATUS:" $mr2.StatusCode
} catch {
    Write-Host "NO-COOKIE STATUS:" $_.Exception.Response.StatusCode.Value__
}
