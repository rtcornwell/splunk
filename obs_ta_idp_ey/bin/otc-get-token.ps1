﻿param(
    [string]$user1,
    [string]$pw1,
    [string]$idp
)
try{
$token = "MIIFSAYJKoZIhvcNAQcCoIIFOTCCBTUCAQExDTALBglghkgBZQMEAgEwggMWBgkqhkiG9w0BBwGgggMHBIIDA3sidG9rZW4iOnsiZXhwaXJlc19hdCI6IjIwMTktMDktMjVUMDc6MzU6NTAuNjUyMDAwWiIsIm1ldGhvZHMiOlsicGFzc3dvcmQiXSwiY2F0YWxvZyI6W10sInJvbGVzIjpbeyJuYW1lIjoidGVfYWdlbmN5IiwiaWQiOiI0MWNlNTg1N2M5NGM0Nzc1YjZjYzUzZDVmZWViYTQ0NSJ9LHsibmFtZSI6InRlX2FkbWluIiwiaWQiOiI2OTliZDYyY2RhMzA0ZDJjYWQwM2ZkMmZiMTkwYjhjZiJ9LHsibmFtZSI6InNlY3VfYWRtaW4iLCJpZCI6ImE3Yzc5NzgwYmVhYTQ4NzhiZTc0YjU5MTAxM2VkNTViIn0seyJuYW1lIjoib3BfZ2F0ZWRfY2NlX3N3aXRjaCIsImlkIjoiMCJ9XSwiZG9tYWluIjp7Inhkb21haW5fdHlwZSI6IlRTSSIsIm5hbWUiOiJPVEMwMDAwMDAwMDAwMTAwMDAxMDUwMSIsImlkIjoiYTAxYWFmY2Y2Mzc0NGQ5ODhlYmVmMmIxZTA0YzVjMzQiLCJ4ZG9tYWluX2lkIjoiMDAwMDAwMDAwMDEwMDAwMTA1MDEifSwiaXNzdWVkX2F0IjoiMjAxOS0wOS0yNFQwNzozNTo1MC42NTIwMDBaIiwidXNlciI6eyJkb21haW4iOnsieGRvbWFpbl90eXBlIjoiVFNJIiwibmFtZSI6Ik9UQzAwMDAwMDAwMDAxMDAwMDEwNTAxIiwiaWQiOiJhMDFhYWZjZjYzNzQ0ZDk4OGViZWYyYjFlMDRjNWMzNCIsInhkb21haW5faWQiOiIwMDAwMDAwMDAwMTAwMDAxMDUwMSJ9LCJuYW1lIjoicm9iZXJ0Y29ybndlbGwiLCJwYXNzd29yZF9leHBpcmVzX2F0IjoiMjAyMC0wMy0wN1QxNTo0MDoxNi4wMDAwMDAiLCJpZCI6IjZmZTc3NjRhNGZlMzRmNWY5NjNhOTgzZjFmZjhkMjRiIn19fTGCAgUwggIBAgEBMFwwVzELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVVuc2V0MQ4wDAYDVQQHDAVVbnNldDEOMAwGA1UECgwFVW5zZXQxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbQIBATALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggGAe3VB7gUt7cj6qjidtHC-abIKsq5WAWKOdR3txb+THA2j9ZcKChSd0Zg3eE6liupsi3i4+IPmp33w2wllNvLGRmxXJ+gBO69NWWKbJml71+KBrDWRzh44u5ejYxmRl1V3YORsTBHH7I6x11ExL2b-JY52sRgtJzMhwXRXvxY0AyJPCobKenwMABtbUKorxyMVvExb+HFVmc8JfKk0NSSpH50gx5RupEgUS7LVw5bXvIF1V5nHcDuewoL5chW0kxlCPNs1CNFcP8-pmwwS3Sw9-Ad26zodszEFRgcBe4PmHpAr-08i+80Dc9dq4caL3IPNqy0ODhVbQScDdAy5EE0VOwcAL8vlW2wYIzRXLOoPM21R5kC6Z9vSQweo68fEoYhh6LZ8FkrYts4FMj7QjJzxuieRM5SGyQLDaH4s9w5dO2f4Bjtx3EHuoZSytdPXiZ9WY-WT3wE7R2FZ0iouNQnFE6LqOVJumxXxLZDFo3CRcCSeazBcLeIautEm0VdIhCMI"
#$token | out-file -FilePath "C:\temp\token.txt"
write-output $token
}
catch{
write-output "Failed to get OTC token $_ .."
}