# Packaging

Templates for the Scoop, winget, and Chocolatey packages. `render.py` fills
them in with the version, download URLs, and checksums from a release's
`SHA256SUMS.txt`. When a GitHub release is published,
`.github/workflows/packages.yml` publishes to winget and Chocolatey, and the
Scoop bucket updates itself.

To render them by hand, for a first submission or to check a change:

```bash
gh release download v0.1.0 --pattern SHA256SUMS.txt
python3 packaging/render.py 0.1.0 SHA256SUMS.txt out
```

## Upgrades

Every channel upgrades by installing the new version over the old one:

- **winget and Chocolatey** run the new Inno Setup installer silently. Its
  fixed `AppId` makes it replace the existing install in place, in the same
  folder and the same mode (per user or all users). winget finds the install
  through `ProductCode`, the Add/Remove Programs key that `AppId` produces.
- A running Hivemend is asked to close first. It refuses while a repair,
  restore, or cleanup is running, and Setup then stops without changing
  anything; it is never restarted afterwards, so it cannot come back with
  the installer's administrator rights.
- **Scoop** unpacks each version into its own folder and switches `current`
  over to it.
- Backups, settings, and the ignore list live in `%LOCALAPPDATA%\HiveMend`
  (and the administrator backup store), never in the install folder, so
  upgrades and uninstalls keep them.

CI checks this on every pull request (`installer\test-installer.ps1`): a
per-user and an all-users install, an upgrade with Hivemend running, a
reinstall, and an uninstall. A release build also upgrades from the last
published release's installer.

Never change the `AppId` in `installer/hivemend.iss`: a new one would install
next to the old version instead of replacing it.

## Scoop

The bucket is its own repository, `Tuigse-oss/scoop-hivemend`, so `main` here
never needs a bot commit. Its `update` workflow runs every six hours (or on
demand from its Actions tab), finds the latest published Hivemend release,
renders `scoop/hivemend.json` with this folder's `render.py` at that tag, and
commits it. It uses that repository's own token, so no secret is needed.

GitHub pauses scheduled workflows in a public repository after 60 days without
activity; if a release is not picked up, re-enable or run the `update`
workflow there.

Users install with:

```powershell
scoop bucket add hivemend https://github.com/Tuigse-oss/scoop-hivemend
scoop install hivemend
```

## Switching on winget and Chocolatey

Each needs a repository variable (Settings > Secrets and variables > Actions >
Variables) and a secret. Without the variable, its job is skipped.

### winget: `PUBLISH_WINGET=true`, secret `WINGET_TOKEN`

1. Fork `microsoft/winget-pkgs` to the account that will open the pull
   requests.
2. Create a classic personal access token on that account with the
   `public_repo` scope and add it as the secret `WINGET_TOKEN`.
3. A new package is reviewed by hand, so submit the first version yourself:
   render the manifests as above, then on Windows run
   `wingetcreate submit out\winget --token <token>`. Turn the variable on once
   that pull request is merged; later versions are submitted by the workflow.

Users install with `winget install TUIGSE.Hivemend`.

### Chocolatey: `PUBLISH_CHOCOLATEY=true`, secret `CHOCOLATEY_API_KEY`

1. Create an account at https://community.chocolatey.org and copy the API key
   from the account page into the secret `CHOCOLATEY_API_KEY`.
2. Every version is checked by Chocolatey's moderators before it is listed;
   the first one is reviewed by a person and can take a while.

Users install with `choco install hivemend` (from an administrator prompt;
Chocolatey installs for all users).
