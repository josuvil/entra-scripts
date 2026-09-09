# Microsoft Graph serviceProvisioningErrors group scan

`MS-Graph-Enumerate-ServiceProvisioningErrors.ps1` scans Microsoft Entra ID security groups and distribution groups for Microsoft Graph `serviceProvisioningErrors` and exports the findings to CSV.

The script is intended for tenant administrators who need a repeatable way to locate groups that Microsoft Entra ID or downstream Microsoft 365 services could not provision, update, or synchronize cleanly.

## What the script does

- Connects to Microsoft Graph using one of three authentication modes:
  - Interactive delegated sign-in
  - Service principal certificate authentication
  - Managed identity
- Verifies required Microsoft Graph PowerShell modules and Graph permissions before scanning.
- Loads all non-Microsoft 365 security groups and all distribution groups in the tenant.
- Queries each group for `serviceProvisioningErrors`.
- Runs the scan in parallel with retry and backoff handling for Microsoft Graph throttling.
- Writes:
  - A full detail CSV containing every discovered provisioning error.
  - A skipped-groups CSV when individual groups could not be queried.
  - A transcript log for operational troubleshooting.

## Why use it

Provisioning errors can be difficult to spot from normal group administration views, especially in large tenants. A group may appear to exist but still contain stale, unresolved, or service-specific provisioning failures that affect downstream behavior.

Use this script to:

- Find security groups and distribution groups with unresolved service provisioning problems.
- Create a tenant-wide inventory of group provisioning health.
- Identify groups that may require repair, recreation, ownership review, or Microsoft support escalation.
- Compare scan results over time to detect newly introduced or persistent failures.
- Collect evidence before and after cleanup work to confirm whether corruption symptoms were resolved.

## What errors it finds

The primary findings are Microsoft Graph `serviceProvisioningErrors` returned from group objects. For each error, the export includes:

| Column | Meaning |
| --- | --- |
| `GroupId` | Microsoft Entra object ID of the affected group. |
| `GroupName` | Display name of the affected group at scan time. |
| `GroupType` | `SecurityGroup` or `DistributionGroup`. |
| `ODataType` | Graph type of the provisioning error object. |
| `ServiceInstance` | The service or workload that reported the provisioning issue. |
| `CreatedDateTime` | When the provisioning error was created. |
| `IsResolved` | Whether Graph reports the error as resolved. |
| `ErrorDetail` | Detailed service-provided diagnostic text for the error. |

The script also records scan failures separately so administrators can distinguish object provisioning errors from operational scan issues.

Skipped group reasons include:

| Reason | Meaning |
| --- | --- |
| `AuthExpired_401` | Authentication expired during the scan. Re-authenticate and scan again. |
| `Forbidden_403` | The current identity lacks access to read the group or required properties. |
| `RetryBudgetExhausted_429` | Microsoft Graph throttling continued after the retry budget was exhausted. |
| `NetworkError` | A request failed without an HTTP status code, commonly because of transient network issues. |
| `Error_HTTPNNN` | Another Microsoft Graph HTTP error occurred. The numeric status code is included in the reason. |

## How the exports help detect object corruption

`serviceProvisioningErrors` are useful indicators of possible group object corruption because they expose cases where the directory object and one or more backing services disagree about the object state.

The CSV exports help by making those signals searchable and comparable:

- `GroupId` gives a stable identifier for correlation with audit logs, support cases, and other exports.
- `ServiceInstance` shows which downstream service is failing to provision or synchronize the group.
- `CreatedDateTime` helps identify whether the issue is new, recurring, or long-standing.
- `IsResolved` separates historical errors from active unresolved failures.
- `ErrorDetail` preserves the diagnostic text needed to recognize malformed attributes, stale references, provisioning conflicts, or service-specific failures.
- Repeated scans can be compared to identify groups whose errors persist after normal synchronization cycles, which is a stronger corruption signal than a single transient error.

These exports do not prove corruption by themselves, but they provide a focused list of objects that deserve deeper investigation.

## Requirements

- PowerShell 7.2 or later.
- Microsoft Graph PowerShell modules:
  - `Microsoft.Graph.Authentication` version 2.0.0 or later.
  - `Microsoft.Graph.Groups` version 2.0.0 or later.
- Microsoft Graph permissions:
  - `Group.Read.All`
  - `Directory.Read.All`

For app-only execution, grant the required application permissions and admin consent to the service principal. For interactive execution, the script requests the required delegated scopes.

## Configuration

Edit the configuration section at the top of `MS-Graph-Enumerate-ServiceProvisioningErrors.ps1` before running:

- `$AuthMode`: `Interactive`, `ServicePrincipal`, or `ManagedIdentity`.
- `$AppId`, `$TenantId`, and `$CertificateThumbprint`: required only for service principal authentication.
- `$MaxParallel`, `$InitialBackoffSec`, `$MaxBackoffSec`, and `$MaxRetries`: scan concurrency and throttling behavior.
- `$OutDir`: directory where CSV and transcript files are written.

The default output directory is `C:\Temp`.

## Output files

Each run creates timestamped files in `$OutDir`:

- `group_errors_<timestamp>.csv`: full provisioning error detail for affected groups.
- `group_errors_skipped_<timestamp>.csv`: groups that could not be queried, created only when skipped groups exist.
- `group_errors_transcript_<timestamp>.log`: PowerShell transcript for the run.

The results CSV also includes header metadata such as scan start time, total groups scanned, number of groups with errors, skipped group count, elapsed time, and transcript path.

## Running the script

From PowerShell 7:

```powershell
./MS-Graph-Enumerate-ServiceProvisioningErrors.ps1
```

Review the console summary after completion, then inspect the generated CSV files in `$OutDir`.

## Security notes

The generated files may contain sensitive tenant, group, and provisioning diagnostic data. Store them in a restricted location, limit access to administrators who need the information, and handle the exports according to your organization's data protection requirements.

The script warns when the configured output directory appears to grant broad write access.

## Support disclaimer

This script is provided as-is, without warranty, and is not a supported Microsoft product. High-volume Microsoft Graph queries may be throttled if used aggressively. Review and tune the scan settings for your tenant size before running in production.
