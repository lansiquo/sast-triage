# Making the check required

sast-triage reports through a Check Run. It blocks a merge only when branch protection requires that check. `protection.json` requires the `PRSecurityScan` check (the default `PRSEC_CHECK_NAME`), one approving review (from a code owner, where the repository has a CODEOWNERS file), resolved conversations and linear history, and blocks force pushes and branch deletion, for admins too.

Apply it to a repository where the App is installed (change `context` first if you set `PRSEC_CHECK_NAME`):

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input docs/branch-protection/protection.json
```

Nothing here is applied to this repository.
