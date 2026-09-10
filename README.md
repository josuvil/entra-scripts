# Entra Scripts

This repository holds a collection of scripts for administrators who want to keep a Microsoft Entra ID directory healthy. Each project lives in its own subdirectory with a dedicated README describing its purpose, requirements, and usage.

## Projects

- [`group-provisioning-error-scan/`](group-provisioning-error-scan/README.md): Scans Microsoft Entra ID security groups and distribution groups for Microsoft Graph `serviceProvisioningErrors` and exports the findings to CSV, helping administrators locate groups with unresolved provisioning issues.

## Support disclaimer

These scripts are provided as-is, without warranty, and are not supported Microsoft products. Review and test each script in a non-production environment before using it against a production tenant.
