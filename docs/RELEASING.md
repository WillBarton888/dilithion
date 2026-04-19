# Releasing Dilithion

The canonical checklist for cutting a release. The public deliverables are
built on GitHub Actions (macOS, Windows) and locally on our Linux build
server, then attached to a GitHub Release.

> Maintainers only. If you're contributing a PR, this doesn't apply to you —
> see [../CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Prerequisites

- Write access to `dilithion/dilithion`
- `gh` (GitHub CLI) authenticated — `gh auth login`
- SSH access to the Linux build host (NYC seed node)
- GPG key registered with GitHub (signed tags are required — see
  [../README.md](../README.md) badges for the expected verified state)

---

## Version scheme

Dilithion uses [Semantic Versioning](https://semver.org/):

- `MAJOR.MINOR.PATCH` — e.g. `v4.0.16`
- **Major** bumps: consensus changes requiring a hard fork
- **Minor** bumps: protocol extensions, new RPCs, significant features
- **Patch** bumps: bug fixes, optimizations, non-breaking changes

The version is baked in at build time from the latest git tag (see
`Makefile`). Untagged working copies report `dev`.

---

## Checklist

### 1. Pre-release QA

- [ ] All CI workflows green on `main`
  ```bash
  gh run list --branch main --limit 10
  ```
- [ ] Local test suite passes
  ```bash
  make clean && make -j$(nproc) && make tests && make run-tests
  ```
- [ ] Manual smoke test on at least one seed node (IBD from scratch + one mining session)
- [ ] `CHANGELOG.md` updated — move entries from `[Unreleased]` into a new `[vX.Y.Z] — YYYY-MM-DD` section
- [ ] No uncommitted changes:
  ```bash
  git status
  ```

### 2. Tag

Signed tags only — unsigned tags are rejected by branch protection.

```bash
git tag -s vX.Y.Z -m "Dilithion vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

The tag push triggers:
- `build-linux.yml` — Linux x64 tarball
- `build-macos.yml` — macOS x64 tarball
- `build-windows.yml` — Windows x64 zip
- DilV equivalents (`build-dilv-*.yml`)

### 3. Build Linux locally (CI covers macOS + Windows)

The Linux binary is built on the NYC build host and uploaded manually to keep
its build environment stable and auditable:

```bash
ssh root@<build-host> "cd /root/dilithion && git fetch --tags && git checkout vX.Y.Z && make clean && make -j4"

VERSION=vX.Y.Z ssh root@<build-host> "cd /root/dilithion && ./package-linux-release.sh"
scp root@<build-host>:/root/dilithion/releases/dilithion-vX.Y.Z-mainnet-linux-x64.tar.gz releases/
gh release upload vX.Y.Z releases/dilithion-vX.Y.Z-mainnet-linux-x64.tar.gz
```

### 4. Build a bootstrap snapshot (optional but recommended)

Lets new users skip initial block download (IBD). Only do this when the
build host is fully synced.

```bash
ssh root@<build-host> "cd /root/dilithion && ./package-bootstrap.sh"
scp root@<build-host>:/root/bootstrap-mainnet-*.tar.gz releases/
gh release upload vX.Y.Z releases/bootstrap-mainnet-*.tar.gz
```

### 5. Watch CI

```bash
gh run watch
gh run list --workflow=build-macos.yml --limit 3
gh run list --workflow=build-windows.yml --limit 3
```

CI jobs upload their artifacts directly to the release if GitHub Actions has
write permission (repo setting: `Settings → Actions → General → Workflow
permissions → Read and write permissions`).

### 6. Verify artifacts

```bash
gh release view vX.Y.Z --json assets --jq '.assets[].name'
```

Expected attachments:
- `dilithion-vX.Y.Z-mainnet-linux-x64.tar.gz`
- `dilithion-vX.Y.Z-mainnet-macos-x64.tar.gz`
- `dilithion-vX.Y.Z-mainnet-windows-x64.zip`
- (optional) `bootstrap-mainnet-*.tar.gz`
- DilV equivalents if relevant

If any are missing, see **Troubleshooting** below.

### 7. Write release notes

`gh release edit vX.Y.Z --notes-file release-notes.md` or through the GitHub UI.

Format:

```markdown
## Summary

One-paragraph description of what this release does.

## Upgrade notes

- Any migration steps required
- Any breaking changes
- Consensus activation heights, if applicable

## Changes since vA.B.C

- **feat:** new RPC `xyz` (#123)
- **fix:** resolves crash on Windows when ...
- **chore:** ...

Full diff: https://github.com/dilithion/dilithion/compare/vA.B.C...vX.Y.Z
```

### 8. Publish

Flip the release from draft / pre-release to published in the GitHub UI, or:

```bash
gh release edit vX.Y.Z --prerelease=false --draft=false
```

### 9. Deploy to seed nodes (rolling)

**Never update all seed nodes simultaneously.** Keep at least 3 running at all
times so the network stays healthy during the rollout.

```bash
# For each seed node, one at a time:
ssh root@<seed> "cd /root/dilithion && git fetch --tags && git checkout vX.Y.Z && make clean && make -j4"
# Restart via wrapper (do NOT kill the wrapper first — restart the node,
# then verify it re-syncs before moving to the next seed)
```

See internal ops notes for the exact seed-node list and wrapper conventions.

### 10. Announce

- [ ] Discord `#announcements`
- [ ] Telegram `@dilithion_news`
- [ ] Mastodon `@dilithion@mastodon.social`
- [ ] Website download page updated (if the URL is versioned rather than
      using the `latest` redirect)

---

## Troubleshooting

### macOS CI build succeeds but didn't upload
Historical 403 on the upload step. Download the artifact and upload manually:
```bash
gh run list --workflow=build-macos.yml --limit 3
gh run download <RUN_ID> -n dilithion-vX.Y.Z-mainnet-macos-x64 -D releases/ci-macos-vX.Y.Z
gh release upload vX.Y.Z releases/ci-macos-vX.Y.Z/dilithion-vX.Y.Z-mainnet-macos-x64.tar.gz
```

### Build failed on Windows with missing DLL
The packaging script needs the 6 runtime DLLs in MSYS2's `/mingw64/bin/`:
`libwinpthread-1.dll`, `libgcc_s_seh-1.dll`, `libstdc++-6.dll`,
`libleveldb.dll`, `libcrypto-3-x64.dll`, `libssl-3-x64.dll`. If any moved
with an MSYS2 upgrade, update `package-windows-release-github.sh`.

### I tagged the wrong commit
Delete both the local tag and the remote tag, then re-tag:
```bash
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
# Fix whatever needed fixing, then re-tag as in Step 2.
```

Do **not** force-push tags that have already been consumed by CI — the
uploaded artifacts will point to a commit that no longer matches the tag.
Prefer a new patch version (`vX.Y.(Z+1)`).

---

## Release cadence

- **Patch releases:** as needed for bug fixes (no fixed cadence)
- **Minor releases:** every 2–4 weeks when features ship
- **Major releases:** consensus-breaking changes only, coordinated with
  activation height and community notice ≥14 days in advance

---

## What next

- [BUILDING.md](BUILDING.md) — how to build locally
- [TESTING.md](TESTING.md) — how to validate before tagging
- [../CHANGELOG.md](../CHANGELOG.md) — release history
