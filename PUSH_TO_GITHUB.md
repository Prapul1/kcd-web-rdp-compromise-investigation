# Pushing This Repo to GitHub

This folder is already an initialized git repository with one commit
containing the full report and screenshots.

1. Create a new **empty** repository on GitHub (no README/license/gitignore
   added), e.g. `kcd-web-rdp-compromise-investigation`.
2. From inside this extracted folder, run:

```powershell
git remote add origin https://github.com/<your-username>/kcd-web-rdp-compromise-investigation.git
git branch -M main
git push -u origin main
```

If you use SSH instead:

```powershell
git remote add origin git@github.com:<your-username>/kcd-web-rdp-compromise-investigation.git
git branch -M main
git push -u origin main
```

If `git remote add origin` errors with "not a git repository," it means the
`.git` folder didn't survive extraction (this can happen with some zip
tools). In that case, just re-initialize it fresh from inside this folder:

```powershell
git init
git config user.email "you@example.com"
git config user.name "Your Name"
git add -A
git commit -m "Add KCD-Web RDP compromise incident investigation (INC-2026-0223-KCD)"
git remote add origin https://github.com/<your-username>/kcd-web-rdp-compromise-investigation.git
git branch -M main
git push -u origin main
```
