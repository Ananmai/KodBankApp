$loginBody = '{"customer_email":"arjun@kodbank.com","customer_password":"test@123"}'
$lr = Invoke-RestMethod -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $loginBody
$token = $lr.token
Write-Host "TOKEN (first 40):" $token.Substring(0, [Math]::Min(40, $token.Length)) "..."
Write-Host ""

$headers = @{ Authorization = "Bearer $token" }
$me = Invoke-RestMethod -Uri 'http://localhost:3000/api/me' -Headers $headers
Write-Host "✅ /api/me name:" $me.customer_name

$prof = Invoke-RestMethod -Uri 'http://localhost:3000/api/profile' -Headers $headers
Write-Host "✅ /api/profile accno:" $prof.account_number

$txns = Invoke-RestMethod -Uri 'http://localhost:3000/api/transactions' -Headers $headers
Write-Host "✅ /api/transactions count:" $txns.Count
