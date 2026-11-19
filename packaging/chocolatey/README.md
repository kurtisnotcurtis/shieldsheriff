# Chocolatey Packaging for ShieldSheriff

These templates are rendered and packed into `shieldsheriff.<version>.nupkg` by [`.github/workflows/release.yml`](../../.github/workflows/release.yml) during each GitHub Release.

## CalVer Version Normalization

ShieldSheriff uses `YYYY.0M.MICRO` CalVer (for example `2026.08.1` or `2026.11.8`). Because NuGet/Chocolatey strips leading zeros from numeric version segments, the workflow normalizes each segment (`2026.08.1` -> `2026.8.1`) for the `.nuspec` `<version>` while keeping the exact `__TAG__` (`v2026.08.1`) and `__VERSION__` (`2026.08.1`) in download URLs.

## Testing Locally & Submitting

1. Download `shieldsheriff.<version>.nupkg` from the GitHub Release assets (or render the templates and run `choco pack`).
2. Test local installation & uninstallation in an elevated PowerShell session:
   ```powershell
   choco install shieldsheriff -s . -y
   shiesh
   choco uninstall shieldsheriff -y
   ```
3. Push to the Chocolatey Community Repository:
   ```powershell
   choco push shieldsheriff.<version>.nupkg --source https://push.chocolatey.org/ --api-key <YOUR_API_KEY>
   ```
4. To automate future pushes in GitHub Actions, add your Chocolatey API key as the `CHOCO_API_KEY` repository secret.

> **Note:** Initial submissions to `community.chocolatey.org` go through automated verification and human moderation before becoming publicly indexed (`choco install shieldsheriff`). Once approved as a Trusted Package, automated CI pushes clear automatically after passing automated checks.
