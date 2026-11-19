# Scoop Packaging for ShieldSheriff

[`shieldsheriff.json`](shieldsheriff.json) is the Scoop manifest template rendered by [`.github/workflows/release.yml`](../../.github/workflows/release.yml) into `shieldsheriff.json` on each GitHub Release.

## Publishing via a Personal Bucket (Available Immediately)

Official `ScoopInstaller/Extras` requires 100+ GitHub stars / 50+ forks. Until then, you can host a personal Scoop bucket:

1. Create a repository named `scoop-bucket` under `kurtisnotcurtis` from [`ScoopInstaller/BucketTemplate`](https://github.com/ScoopInstaller/BucketTemplate).
2. Add the rendered `shieldsheriff.json` (from any GitHub Release asset) as `bucket/shieldsheriff.json`.
3. Users install with:
   ```powershell
   scoop bucket add kurtisnotcurtis https://github.com/kurtisnotcurtis/scoop-bucket
   scoop install shieldsheriff
   ```
4. To automate updates from GitHub Releases, add a repository secret named `SCOOP_BUCKET_TOKEN` (a GitHub PAT with write access to `kurtisnotcurtis/scoop-bucket`; optionally set repository variable `SCOOP_BUCKET_REPO` if using a different `<owner>/<repo>`).

## Local Validation

```powershell
# Install directly from a rendered manifest file:
scoop install .\shieldsheriff.json
```
