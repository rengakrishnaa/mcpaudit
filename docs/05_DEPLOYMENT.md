# Deployment

Cost: free, no card, no trial that expires. That constraint is what shaped the
architecture — a demo that needs credits topped up eventually is a demo nobody bothers
trying.

Time: about 20 minutes.

## What you're deploying

```
GitHub Actions (scheduled, free)
    scans servers inside Docker
    writes site/*.html + site/api/*.json
    commits data/mcpaudit.db + data/history.jsonl back to the repo   ← persistence
    ↓
GitHub Pages (free, CDN, no cold start)
    https://<you>.github.io/mcpaudit/
```

Nothing runs between scans. There's no server to sleep, no database to expire, no dyno to
suspend, and nothing that can bill you.

## Step 1 — push the repository

```bash
cd mcpaudit
git init
git add -A
git commit -m "MCPAudit: MCP server security scanner and trust registry"
gh repo create mcpaudit --public --source=. --push
```

Or create it in the browser and:

```bash
git remote add origin https://github.com/<you>/mcpaudit.git
git branch -M main
git push -u origin main
```

The repository needs to be public. Public repos get unlimited Actions minutes; private ones
get 2,000/month, and a nightly Docker scan will eat through that.

## Step 2 — turn on Pages

Repository → Settings → Pages → Build and deployment → Source: **GitHub Actions**.

Not "Deploy from a branch" — the workflow uploads an artifact and deploys it directly, and
the branch option would look for a `gh-pages` branch that doesn't exist here.

## Step 3 — let Actions write to the repo

Settings → Actions → General → Workflow permissions → **Read and write permissions** →
Save.

Without this the nightly job can't commit `data/mcpaudit.db`, which means no history
survives between runs and the rug-pull rule (MCP007) can never fire. This is the one
setting that breaks the product silently instead of breaking the build loudly.

## Step 4 — run it once by hand

Actions → "scan and publish" → Run workflow.

Leave `use_registry` off and `limit` at 40 for the first run. Expected log:

```
Scan the bundled examples          ✓  ~10s
Scan real servers                  ✓  a few minutes (Docker pulls node:22-slim once)
Export the git-diffable history    ✓
Build the static site              ✓
Commit the updated database        ✓  scan: 2026-08-18 [skip ci]
deploy                             ✓  https://<you>.github.io/mcpaudit/
```

Open the URL — that's the live link.

## Seeding real history

The registry's whole value is history, and on day one there is none. Run the scan daily
for the first week before putting the link anywhere permanent — seven data points make the
fingerprint history look like a real record; one data point just looks like an empty
schema. The nightly cron does this automatically once it's running; you just need to have
pushed a week ahead of when you actually need the link.

## Local development

```bash
python -m mcpaudit demo                    # no Docker, no network, no deps
python -m mcpaudit scan --seed data/seed_servers.json   # needs Docker
python -m mcpaudit check --npm @modelcontextprotocol/server-filesystem /tmp
python -m mcpaudit site --out site
python -m mcpaudit export --out data/history.jsonl
python -m mcpaudit report npm:@modelcontextprotocol/server-filesystem
python -m mcpaudit prune                   # delete leftover sandbox images
```

Don't run `scan` against real servers without Docker. `sandbox.prepare()` refuses on
purpose — `npm install` and `pip install` execute arbitrary code from the package at
install time, and that should never happen directly on your own machine.

## Troubleshooting

**Pages deploys but the site is a 404.**
Pages source is set to "Deploy from a branch" — change it to "GitHub Actions" (Step 2).

**The nightly job runs but the site never changes.**
Workflow permissions are read-only, so the commit step failed silently (Step 3).

**Rug pull never fires even though a description changed.**
Check that `data/mcpaudit.db` is actually in the repository:
```bash
git ls-files data/
```
If it's missing, `.gitignore` is excluding it somehow. The shipped `.gitignore`
deliberately doesn't — the repo is the database.

**CSS is missing, or a page 404s after adding a file.**
Missing `.nojekyll`. GitHub Pages runs Jekyll by default and drops paths starting with an
underscore. `site.build()` writes this file; confirm it survived the upload.

**Scanning real servers times out.**
`--install-timeout` defaults to 300s. Some npm packages are slow to install — raise the
timeout, or drop the server from the seed file. One bad package shouldn't stop the site
from publishing, which is why that workflow step has `continue-on-error: true`.

**Actions minutes ran out.**
The repository is private. Make it public.

## Costs, itemised

| | Cost |
|---|---|
| GitHub Actions (public repo) | free, unlimited |
| GitHub Pages | free, 100 GB/month bandwidth |
| Docker Hub base image pulls | free at this rate |
| SQLite | it's a file |
| LLM judge | off by default — the only thing here that could ever cost money |
| **Total** | **$0/month** |

## Optional: turning on the LLM judge

Only worth doing if you want it, and only for a manual run — the public registry stays
generated without it by default.

```bash
gh secret set ANTHROPIC_API_KEY
pip install 'mcpaudit[llm]'
python -m mcpaudit scan --llm --limit 20
```
