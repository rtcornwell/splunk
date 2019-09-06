param(
    [string]$user1,
    [string]$pw1
)
try{
write-Host "Starting Powershell"
$token = "asnasnsasadnascnkasdnasdsknasdklnasdsknasdk"
#$token | out-file -FilePath "C:\temp\token.txt"
write-output $token
}
catch{
write-output "Failed to get OTC token $_ .."
}