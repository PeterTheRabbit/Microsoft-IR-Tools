<#
This PowerShell script connects to Microsoft Graph with audit log read permissions, loads a list of suspicious IP addresses from an input CSV ("suspicious_ips.csv"), queries Azure AD sign-in audit logs for the past 30 days (paginating results), filters for sign-ins originating from those IPs, and exports matching details (timestamp, user principal name, IP, app name, success/failure status) to an output CSV ("user_signins_from_ips.csv") for security monitoring or incident response.
#>

# Set paths
$inputCsv = "suspicious_ips.csv"
$outputCsv = "user_signins_from_ips.csv"

# Date range (edit as needed)
$startDate = (Get-Date).AddDays(-30).ToString("o")
$endDate = (Get-Date).ToString("o")

# Connect to Microsoft Graph
Import-Module Microsoft.Graph
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Load IPs from CSV
$suspiciousIps = Import-Csv $inputCsv | Select-Object -ExpandProperty IPAddress
$suspiciousIpSet = [System.Collections.Generic.HashSet[string]]::new()
$suspiciousIps | ForEach-Object { $suspiciousIpSet.Add($_.Trim()) }

# Container for results
$results = @()

# Page through sign-ins
$nextLink = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startDate and createdDateTime le $endDate&`$top=1000"

do {
    $response = Invoke-RestMethod -Uri $nextLink -Headers @{ Authorization = "Bearer $((Get-MgContext).AccessToken)" }
    foreach ($record in $response.value) {
        $ip = $record.ipAddress
        if ($suspiciousIpSet.Contains($ip)) {
            $results += [PSCustomObject]@{
                Timestamp         = $record.createdDateTime
                UserPrincipalName = $record.userPrincipalName
                IPAddress         = $record.ipAddress
                AppDisplayName    = $record.appDisplayName
                Status            = $record.status.errorCode -eq 0 ? "Succeeded" : "Failed"
            }
        }
    }

    $nextLink = $response.'@odata.nextLink'
} while ($nextLink)

# Export to CSV
$results | Export-Csv $outputCsv -NoTypeInformation -Encoding UTF8
Write-Host "Sign-in results exported to: $outputCsv"