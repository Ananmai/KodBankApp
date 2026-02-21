$body = '{"customer_email":"arjun@kodbank.com","customer_password":"test@123"}'
$response = Invoke-WebRequest -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $body -SessionVariable session

Write-Host "=== Status ===" $response.StatusCode
Write-Host ""
Write-Host "=== Set-Cookie Header ==="
$cookie = $response.Headers["Set-Cookie"]
if ($cookie) {
    Write-Host $cookie
    Write-Host ""
    if ($cookie -match "HttpOnly") { Write-Host "HttpOnly: YES" }
    if ($cookie -match "SameSite=([^;]+)") { Write-Host "SameSite: $($Matches[1])" }
    if ($cookie -match "Max-Age=(\d+)") { Write-Host "Max-Age: $($Matches[1]) seconds" }
} else {
    Write-Host "NO Set-Cookie header found!"
}
Write-Host ""
Write-Host "=== Response Body ==="
$response.Content
