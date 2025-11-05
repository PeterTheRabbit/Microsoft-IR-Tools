# This PowerShell script automates auditing of email access in Microsoft Exchange Online by querying the Unified Audit Log for "MailItemsAccessed" operations (e.g., bind for direct message access, sync for folder synchronization) on specified user accounts from a CSV input. It handles pagination and retries for reliability, processes JSON audit data to extract details like timestamps, IP addresses, client info, message IDs, and folder paths, then exports results to three CSV files: a main audit summary, accessed message IDs, and synced folders. Ideal for infosec investigations into potential unauthorized email access.

# Define important stuff
$userCsvPath = "users_to_audit.csv"
$outputPath = "emailAudit.csv"
$outputMessageIdsPath = "emailAudit_MessageIDs.csv"
$outputSyncedFoldersPath = "emailAudit_SyncedFolders.csv"
$StartDate = "12/25/2024"
$EndDate = Get-Date

# Retry wrapper for transient errors
function Invoke-WithRetry {
    param (
        [ScriptBlock]$Command,
        [int]$Retries = 3,
        [int]$DelaySeconds = 10
    )
    for ($i = 1; $i -le $Retries; $i++) {
        try {
            return & $Command
        } catch {
            Write-Warning "Attempt $i failed: $_"
            if ($i -lt $Retries) { Start-Sleep -Seconds $DelaySeconds }
        }
    }
    throw "All retry attempts failed."
}

# Import Exchange Online module and connect
$InformationPreference = 'SilentlyContinue'
Import-Module ExchangeOnlineManagement
$InformationPreference = 'Continue'
Connect-ExchangeOnline -UserPrincipalName "pmaslowski-az@ivytech.edu"

# Load users from CSV
Write-Host "Reading Users"
$Users = Import-Csv $userCsvPath | ForEach-Object { $_.emailAddress.Trim() }

# Accumulate results
$AllAuditResults = @()

foreach ($user in $Users) {
    Write-Host "Auditing $user"
    $offset = 0
    do {
        $results = Invoke-WithRetry {
            Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate `
                -UserIds $user -Operations "MailItemsAccessed" -ResultSize 5000 -SessionId "IRAudit$user$offset"
        }

        $AllAuditResults += $results

        Start-Sleep -Seconds 10  # Throttle to avoid server errors
        $offset++
    } while ($results.Count -eq 5000)
}

# Process and format results
$Processed = @()
$MessageIdRows = @()
$SyncedFolderRows = @()

foreach ($record in $AllAuditResults) {
    try {
        $data = $record.AuditData | ConvertFrom-Json

        $operationProp = $data.OperationProperties | Where-Object { $_.Name -eq "MailAccessType" }
        $accessType = if ($operationProp) { $operationProp[0].Value.Trim().ToLower() } else { "" }

        switch ($accessType) {
            "bind" {
                if ($data.Folders) {
                    foreach ($folder in $data.Folders) {
                        if ($folder.FolderItems) {
                            foreach ($item in $folder.FolderItems) {
                                $MessageIdRows += [PSCustomObject]@{
                                    Timestamp = $data.CreationTime
                                    UserId = $data.UserId
                                    ClientIPAddress = $data.ClientIPAddress
                                    InternetMessageId = $item.InternetMessageId
                                }
                            }
                        }
                    }
                }
            }
            "sync" {
                $folderPaths = @()

                if ($data.Folders) {
                    foreach ($folder in $data.Folders) {
                        if ($folder.Path) {
                            $folderPaths += $folder.Path
                        }
                    }
                }

                if ($data.Item -and $data.Item.ParentFolder -and $data.Item.ParentFolder.Name) {
                    $folderPaths += $data.Item.ParentFolder.Name
                }

                foreach ($path in $folderPaths | Select-Object -Unique) {
                    $SyncedFolderRows += [PSCustomObject]@{
                        Timestamp = $data.CreationTime
                        UserId = $data.UserId
                        ClientIPAddress = $data.ClientIPAddress
                        SyncedFolder = $path
                    }
                }
            }
        }

        $output = [ordered]@{
            Timestamp                    = $data.CreationTime
            MailAccessType               = $accessType
            UserId                       = $data.UserId
            ClientIPAddress              = $data.ClientIPAddress
            ClientInfoString             = $data.ClientInfoString
            ClientAppId                  = $data.ClientAppId
            AppAccessContext_APIId       = $data.AppAccessContext.APIId
            AppAccessContext_ClientAppId = $data.AppAccessContext.ClientAppId
            FolderPath                   = if ($data.Folders -and $data.Folders[0]) { $data.Folders[0].Path } else { $null }
            InternetMessageId            = if ($data.Folders) {
                                              ($data.Folders | ForEach-Object {
                                                  if ($_.FolderItems) {
                                                      $_.FolderItems | ForEach-Object { $_.InternetMessageId }
                                                  }
                                              }) -join "; "
                                           } else { $null }
            SizeInBytes                  = if ($data.Folders -and $data.Folders[0].FolderItems) { $data.Folders[0].FolderItems[0].SizeInBytes } else { $null }
            ImmutableId                  = if ($data.Folders -and $data.Folders[0].FolderItems) { $data.Folders[0].FolderItems[0].ImmutableId } else { $null }
            ClientRequestId              = if ($data.Folders -and $data.Folders[0].FolderItems) { $data.Folders[0].FolderItems[0].ClientRequestId } else { $null }
            FolderName_FromParent        = if ($data.Folders -and $data.Folders[0].FolderItems -and $data.Folders[0].FolderItems[0].ParentFolder) { $data.Folders[0].FolderItems[0].ParentFolder.Name } else { $null }
            FolderName_FromItemParent    = if ($data.Item -and $data.Item.ParentFolder) { $data.Item.ParentFolder.Name } else { $null }
            FolderName_FromFolderName    = $data.FolderName
            MailboxOwnerUPN              = $data.MailboxOwnerUPN
            OrganizationName             = $data.OrganizationName
            ResultStatus                 = $data.ResultStatus
            Workload                     = $data.Workload
            RawMessage                   = ($record.AuditData -replace "`n", "").Trim()
        }

        $Processed += [PSCustomObject]$output
    } catch {
        Write-Warning "Error at $($record.CreationDate): $_"
    }
}

# Export to CSV
$Processed | Export-Csv $outputPath -NoTypeInformation -Encoding UTF8
$MessageIdRows | Export-Csv $outputMessageIdsPath -NoTypeInformation -Encoding UTF8
$SyncedFolderRows | Export-Csv $outputSyncedFoldersPath -NoTypeInformation -Encoding UTF8

Write-Host "Exported to $outputPath"
Write-Host "Exported to $outputMessageIdsPath"
Write-Host "Exported to $outputSyncedFoldersPath"
