# Winget Packaging for ShieldSheriff

These templates are used by [`.github/workflows/release.yml`](../../.github/workflows/release.yml) to generate ready-to-submit `winget-pkgs` manifests for each GitHub Release.

## Submitting to `microsoft/winget-pkgs`

1. Download the generated `winget-manifests-<version>.zip` from the GitHub Release assets (or generate directly with `wingetcreate`).
2. Validate locally on Windows 11:
   ```powershell
   winget validate --manifest .\kurtisnotcurtis.ShieldSheriff\<version>\
   ```
3. Test local installation:
   ```powershell
   winget settings --enable LocalManifestFiles
   winget install --manifest .\kurtisnotcurtis.ShieldSheriff\<version>\
   ```
4. Submit a PR to `microsoft/winget-pkgs` under:
   `manifests/k/kurtisnotcurtis/ShieldSheriff/<version>/`
   (or run `wingetcreate submit .\kurtisnotcurtis.ShieldSheriff\<version>\`).
