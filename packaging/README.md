# Packaging

Templates for the Scoop, winget, and Chocolatey packages. When a GitHub
release is published, `.github/workflows/packages.yml` fills them in with
`render.py` (version, download URLs, and checksums from the release's
`SHA256SUMS.txt`) and publishes each channel that is switched on.

To render them by hand, for a first submission or to check a change:

```bash
gh release download v0.1.0 --pattern SHA256SUMS.txt
python3 packaging/render.py 0.1.0 SHA256SUMS.txt out
```

## Switching a channel on

Each channel needs a repository variable (Settings > Secrets and variables >
Actions > Variables) and a secret. Without the variable, its job is skipped.

### Scoop: `PUBLISH_SCOOP=true`, secret `SCOOP_BUCKET_DEPLOY_KEY`

The bucket is its own repository, `Tuigse-oss/scoop-hivemend`, so `main` here
never needs a bot commit.

1. Create `Tuigse-oss/scoop-hivemend` (public, with a README).
2. Make a key pair: `ssh-keygen -t ed25519 -N "" -f scoop-deploy -C "hivemend packages"`.
3. In the bucket repository, add `scoop-deploy.pub` under Settings > Deploy
   keys with **Allow write access**.
4. In this repository, add the contents of `scoop-deploy` as the secret
   `SCOOP_BUCKET_DEPLOY_KEY`, then delete both key files.

Users install with:

```powershell
scoop bucket add hivemend https://github.com/Tuigse-oss/scoop-hivemend
scoop install hivemend
```

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
