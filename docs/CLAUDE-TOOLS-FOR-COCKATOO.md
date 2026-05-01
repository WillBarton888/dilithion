# Dilithion Tooling Reference — Everything We've Built

**Audience:** Cockatoo, joining the Dilithion project.
**Purpose:** Complete inventory of the custom skills, Python scripts, shell utilities, hooks, and memory files we've accumulated. So you don't reinvent any of it.
**Companion doc:** [CLAUDE-SETUP-FOR-COCKATOO.md](CLAUDE-SETUP-FOR-COCKATOO.md) — explains the *philosophy* of how Claude is set up. This doc is the **inventory**.
**Date:** 2026-05-01

---

## How to use this doc

Three ways:

1. **Onboarding** — read top to bottom once to know what exists.
2. **Reference** — grep for a keyword when you're stuck ("how do I check node health?" → Ctrl-F "node-status").
3. **Project context** — the *Memory files to read first* section near the bottom is the fastest way to get up to speed on where the project is *right now*.

---

## 1. Read these first to understand where we are

These are the live-state and project-history files. Read in this order:

| File | What it tells you |
|------|------|
| `~/.claude/projects/c--Users-will-dilithion/memory/CURRENT_STATE.md` | Live chain heights, active versions, open incidents. **Auto-injected at session start.** Refresh if older than 7 days. |
| `~/.claude/projects/c--Users-will-dilithion/memory/MEMORY.md` | Master index of all memory files (~150 of them). One line per topic. |
| `~/.claude/projects/c--Users-will-dilithion/memory/recent_sessions.md` | Auto-generated digest of the last several work sessions. |
| `~/.claude/projects/c--Users-will-dilithion/memory/bitcoin_core_port_overview.md` | The big in-progress refactor — porting Bitcoin Core's peer/IBD/AddrMan/CompactBlocks code into Dilithion. Phases 0-5 done, Phase 6 active. |
| `~/.claude/projects/c--Users-will-dilithion/memory/lessons_learned.md` | Failure → fix patterns. Read this before debugging anything. |
| `~/.claude/projects/c--Users-will-dilithion/memory/snippets.md` | Pre-baked RPC, build, and deploy commands. Don't write these from scratch. |
| `[CLAUDE.md](../CLAUDE.md)` (repo root) | Project-facing summary. |
| `[~/.claude/CLAUDE.md](~/.claude/CLAUDE.md)` (Will's machine) | Will's global Claude rules — protocols, RPC syntax, seed-node IPs. |

**Tip:** when Claude opens a session it auto-injects `MEMORY.md` (the index) and runs the `state_refresh.sh` hook to inject live chain state. So you usually don't need to manually open these — Claude already has them.

---

## 2. Custom slash commands (skills)

These live in [`.claude/skills/`](../.claude/skills/) — one folder per skill, each containing a `SKILL.md` markdown file. Type `/<name>` in Claude Code to invoke.

### Daily operations

| Skill | What it does | Args |
|------|------|------|
| `/node-status` | Health check of all seed nodes (mainnet + testnet). Block height, peers, memory, uptime, sync status, flags problems. | `[mainnet\|testnet\|all]` |
| `/start-nodes` | Start seed node(s) via auto-restart wrappers on DIL and/or DilV. Verifies process started, attestation initialized, synced. | `<dil\|dilv\|all> [--node NYC\|LDN\|SGP\|SYD]` |
| `/stop-nodes` | **Gracefully** stop seed node(s). Kills the wrapper FIRST to prevent respawn, then SIGINTs the node. | `<dil\|dilv\|all> [--node NYC\|LDN\|SGP\|SYD] [--force]` |
| `/log-tail` | Tail node logs with freshness verification (timestamp + line-growth check). Filters by severity, searches for patterns. | `<node-name or IP> [--lines N] [--grep pattern] [--errors]` |
| `/debug-node` | Structured debugging. Process check, log freshness, peers, bans, memory, fork detection, RPC health. Single command, full picture. | `<IP or name> [--network mainnet\|testnet]` |

### Investigation & analysis

| Skill | What it does | Args |
|------|------|------|
| `/chain-health` | Both-chain health: block times, fork rate, mining distribution, orphans, peer versions. Catches single-miner exploits early. | `[dil\|dilv\|both] [--blocks 100]` |
| `/mining-report` | Mining distribution analysis. Uses `getfullmikdistribution` RPC. Labels known miners, calculates concentration metrics. | `[dil\|dilv\|both]` |
| `/peer-manage` | Manage peer connections — add/remove peers, clear bans, mesh-check between seeds, diagnose partitions. | `<status\|connect\|ban\|unban\|clear-bans\|mesh-check>` |
| `/test-rpc` | RPC smoke test suite. Runs all key endpoints. Catches regressions before deploy. | `[IP:PORT or local] [--chain dil\|dilv] [--full]` |
| `/debug-report` | Structured triage for external miner bug reports. Intake → classify → reproduce → diagnose → fix → test → verify. | `"<description>" [--chain] [--version] [--node]` |
| `/bridge-status` | Bridge health: relayer process, Aerodrome pool balances, pending txs, arb bot status, contract state. | `[--verbose]` |

### Build, release, infra

| Skill | What it does | Args |
|------|------|------|
| `/build` | Cross-platform smart build. MSYS2 on Windows. Detects header changes → forces clean build. Reports errors clearly. | `[clean] [--target ...] [--jobs N]` |
| `/release` | Full release: tag, build Linux on NYC, monitor CI for macOS/Windows, upload artifacts, verify all 3 binaries present. | `<version> [--skip-linux] [--skip-bootstrap] [--skip-ci] [--draft]` |
| `/bootstrap` | Create + publish blockchain bootstrap snapshots so new users can skip IBD. | `<mainnet\|testnet\|dilv> [--upload vX.X.X]` |
| `/backup` | Backup wallet files, chain data, configs. Verifies integrity. **NEVER deletes originals.** | `<wallet\|chain\|config\|all> [--node IP] [--local]` |
| `/deploy` | Rolling deploy to seed nodes — builds on each, restarts one at a time via wrapper, waits for sync. Enforces 3-nodes-running rule. | `<mainnet\|testnet> [--node ...] [--branch] [--chain]` |
| `/repo-audit` | Scan the repo for cruft (stale scripts, abandoned files). Reports by confidence (definitely / likely / ambiguous). Offers cleanup PR. | (none) |

### Workflow & quality

| Skill | What it does | Args |
|------|------|------|
| `/contract` | Define acceptance criteria **before** coding. Writes `.claude/contracts/active_contract.md`. Use for any moderate/complex task. | `<task description>` |
| `/evaluate` | Adversarial code review of recent changes. Assumes bugs exist and hunts. Run before committing complex features. | `[scope]` (e.g. "staged", "last-commit", a path) |
| `/handoff` | Write structured progress file when finishing a phase or hitting context limit. The next session reads it to pick up cleanly. | `[phase name]` |

### Unattended operation

| Skill | What it does | Args |
|------|------|------|
| `/autonomous` | One iteration of the autonomous Bitcoin Core port pipeline. Picks next queued task, spawns contract/coding/red-team agents, commits on success, halts on blocker. **Wrap with `/loop` for unattended runs.** Has an 8h budget enforced by file-based timer. | `[start\|continue\|stop\|status]` |
| `/loop` (built-in) | Run a prompt or skill on an interval. Combine with `/autonomous` for hands-off port work. | `<interval> <prompt>` |

### Built-in skills worth knowing

These ship with Claude Code itself, not custom:

- `/init` — generate a CLAUDE.md from a fresh codebase
- `/review` — review a pull request
- `/security-review` — security review of pending changes on the current branch
- `/schedule` — create cron-scheduled remote agents
- `/simplify` — review changed code for reuse, quality, efficiency
- `/fewer-permission-prompts` — auto-build allow patterns from your transcript history
- `/update-config` — modify Claude settings.json safely
- `/keybindings-help` — customise keyboard shortcuts

---

## 3. Python utilities

### In the memory folder (`~/.claude/projects/c--Users-will-dilithion/memory/`)

| Script | Purpose | Usage |
|------|------|------|
| `digest_conversations.py` | Digest past Claude conversations into structured memory files. Extracts what was done + decided, weighted by recency. | `python digest_conversations.py --rebuild` (re-digest all)<br>`python digest_conversations.py --recent 20` (last 20)<br>`python digest_conversations.py --session ABC123` |
| `search_conversations.py` | Search past Claude conversations by keyword. Useful for "did I do this before?". | `python search_conversations.py "search term"`<br>`python search_conversations.py "term" --context 3 --role user` |
| `session_metrics.py` | Token-efficiency analysis. Spots wasteful patterns: retries, circles, corrections, dead ends. | `python session_metrics.py --all --trends` |

**These are project-agnostic — copy them to any project's memory folder and they work.**

### In `.claude/`

| Script | Purpose |
|------|------|
| [`.claude/seedq_summary.py`](../.claude/seedq_summary.py) | Summarise seed-node queue state (used by autonomous pipeline) |
| [`.claude/fix_emdash.py`](../.claude/fix_emdash.py) | Strip em-dashes that Claude tends to insert into source files |

### In `scripts/`

| Script | Purpose |
|------|------|
| [`scripts/chain_forensics.py`](../scripts/chain_forensics.py) | Trace coin flows for forensic analysis. Used during the bridge incident. |
| [`scripts/compare_difficulty_results.py`](../scripts/compare_difficulty_results.py) | Compare difficulty algorithm outputs across implementations |
| [`scripts/consolidate-wallet.py`](../scripts/consolidate-wallet.py) | Sweep many small UTXOs into one — useful when a wallet has thousands of mining outputs |

---

## 4. Shell utilities and hooks (`.claude/`)

### Mode control

| File | Purpose |
|------|------|
| [`.claude/MODE`](../.claude/MODE) | One word: `manual` or `autonomous`. Controls the PreToolUse hook. |
| [`.claude/mode.sh`](../.claude/mode.sh) | Switcher. `bash .claude/mode.sh manual` or `... autonomous` or `... status`. Effective on next tool call — no restart. |

### Hooks (wired up in `settings.json`)

| Hook | Triggered on | What it does |
|------|------|------|
| [`.claude/state_refresh.sh`](../.claude/state_refresh.sh) | `SessionStart` | SSHes to NYC seed, pulls live DIL + DilV heights, dumps git log + active incidents into context. ~10s, fails silently. |
| [`.claude/hooks/user_prompt_router.sh`](../.claude/hooks/user_prompt_router.sh) | `UserPromptSubmit` | Greps your prompt for keywords (bridge, MSYS2, DNA, etc.) and injects pointers to relevant memory files. Solves "Claude has the file but doesn't read it." |
| [`.claude/hooks/autonomous_mode_check.sh`](../.claude/hooks/autonomous_mode_check.sh) | `PreToolUse` | If `MODE=autonomous`, blocks `ssh`, `git push`, `gh release`, package installs, edits to settings.json, edits to its own rules. |

### Other

| File | Purpose |
|------|------|
| [`.claude/build_hook.sh`](../.claude/build_hook.sh) | Auto-build trigger after relevant edits |
| [`.claude/precommit_check.sh`](../.claude/precommit_check.sh) | Pre-commit linting / sanity |

---

## 5. Operational shell scripts (`scripts/`)

46 scripts. Categorised:

### Build & deployment
- `build.sh` — clean wrapper around `make`
- `secure-build.sh` — build with extra hardening flags
- `build-with-sanitizers.sh` — ASan/UBSan build for fuzzing
- `install-mainnet-2025-11-07.sh`, `install-testnet-2025-11-07.sh` — installer for fresh seed nodes
- `update-node-2025-11-07.sh` — pull, rebuild, restart on a remote node
- `install-systemd-service.sh` — register a node as a systemd service
- `deploy-phase5-scripts.sh` — phase-specific deploy script

### Health & monitoring
- `health-check-2025-11-07.sh` — quick liveness check
- `daily-health-check-2025-11-10.sh` — daily cron-suitable check
- `alert-handler-2025-11-07.sh` — alert dispatch
- `monitor-fuzzer-resources.sh`, `monitor-fuzzing-status.sh` — fuzzer health
- `test-resource-monitor-2025-11-10.sh` — resource-monitor regression test

### Fuzzing infrastructure (Phase 3 work)
- `build-fuzzers-docker-2025-11-08.sh` — Docker-based fuzzer build
- `build-fuzzers-remote-2025-11-08.sh` — fuzzer build on a remote host
- `deploy-fuzzers-2025-11-08.sh`, `deploy-and-build-fuzzers-2025-11-08.sh` — push to fuzzing host
- `continuous-fuzz.sh`, `run-continuous-fuzz-campaign.sh` — long-running fuzz loop
- `triage-crashes-2025-11-10.sh` — analyse crashing inputs
- `analyze-crash-2025-11-10.sh` — single-crash deep-dive
- `collect-crashes.sh`, `deduplicate-crashes-2025-11-10.sh` — crash management
- `prune-corpus-backup-2025-11-10.sh`, `restore-corpus-2025-11-10.sh`, `backup-corpus-2025-11-10.sh` — corpus lifecycle
- `setup-automation-2025-11-10.sh` — systemd timers for unattended fuzzing

### Test suites
- `run_all_tests.sh`, `run_tests.sh` — entrypoints
- `test_network_sync.sh` — multi-node sync test
- `test_rpc_integration.sh`, `test_rpc_permissions_integration.sh` — RPC test suite
- `test_solo_mining.sh` — solo-miner regression test
- `test_ssl.sh`, `test_websocket.sh` — transport tests
- `test-side-channels.sh` — Dilithium constant-time verification

### One-off / forensic
- `backup-wallet-2025-11-07.sh` — wallet snapshot
- `security-scan-2025-11-07.sh` — repo security scan
- `check-repo-hygiene.sh` — repo-level cruft check
- `gen-embedded-html.sh` — bundle the wallet HTML
- `execute-difficulty-validation.sh` — difficulty algo validation run

**Convention:** scripts dated `-YYYY-MM-DD` were one-off but kept in case we need to repeat. Undated scripts are recurring tools.

---

## 6. Daily workflow recipes

If you want to **X**, do **Y**:

| Task | Command |
|------|------|
| See where everything stands | (Just open Claude — `state_refresh.sh` runs automatically.) |
| Check health of all seed nodes | `/node-status` |
| Tail a node's log without quoting stale data | `/log-tail nyc --lines 100` |
| Investigate a problem on one node | `/debug-node 138.197.68.128` |
| Build the project on Windows | `/build` (uses MSYS2 automatically) |
| Build with a clean rebuild | `/build clean` |
| Deploy a fix to mainnet | `/deploy mainnet --branch <branch>` |
| Cut a release | `/release vX.X.X` |
| Check bridge state | `/bridge-status` |
| Check mining concentration | `/mining-report` |
| Look up something we did weeks ago | `python ~/.claude/projects/c--Users-will-dilithion/memory/search_conversations.py "term"` |
| Refresh the session digest | `python ~/.claude/projects/c--Users-will-dilithion/memory/digest_conversations.py --rebuild` |
| Set acceptance criteria before coding | `/contract <task>` |
| Adversarial review before committing | `/evaluate staged` |
| Hand off a phase to the next session | `/handoff <phase>` |
| Run unattended Bitcoin Core port work overnight | `bash .claude/mode.sh autonomous` then `/loop /autonomous continue` |
| Switch back to interactive | `bash .claude/mode.sh manual` |

---

## 7. Memory files by topic (selected)

The full index is in `MEMORY.md` (~150 entries). The most-load-bearing for understanding *the project*:

### Architecture & strategy
- `bitcoin_core_port_overview.md` — the active major refactor
- `dilv_ecosystem_roadmap.md` — DilV phases 1-10 (authoritative)
- `dilv_speed_vma.md` — block time / finality rationale
- `chain_consensus_history.md` — every hard fork, activation height, ASERT halflife
- `digital_dna_plan.md` — DNA fingerprinting / Sybil defense (multi-phase)
- `sybil_defense_strategy.md` — 5-layer Sybil defense architecture
- `whitepaper_v2.md` — March 2026 rewrite

### Live state & operations
- `CURRENT_STATE.md` — the live snapshot, refreshed weekly minimum
- `bridge_phase8.md` — bridge architecture, contracts, pools, infra
- `bridge_relayer_ops.md` — relayer is systemd-managed; **never start manually**
- `infrastructure_monitoring.md` — monitor.py + Discord alerts
- `network_report.md` — network health methodology

### Incidents (read these to understand what *not* to do)
- `dilv_sybil_incident.md` — DilV v4.0.5 Sybil attacks, full timeline
- `bridge_deficit_incident.md` — April 2026 6,071 wDIL double-mint
- `lessons_learned_bridge_incident.md` — 10 lessons from the bridge incident
- `nyc_fd_storm_apr21.md` — file-descriptor exhaustion on NYC seed
- `incident_2026_04_25_session_lessons.md` — behavioural retrospective

### How we work
- `feedback_red_team_at_every_gate.md` — baseline for consensus-adjacent work
- `feedback_two_layer_review_pattern.md` — when to run both Cursor and a red-team agent
- `feedback_port_first_activation_after.md` — sequencing rule
- `feedback_kiss_bulletproof_dilithion_idiom.md` — three reinforcing engineering principles
- `feedback_session_discipline_collapse.md` — guardrails skipped under pressure
- `feedback_right_size_methodology.md` — risk-class-gated dual-validation

### Personnel & policy
- Will keeps a local memory file about you on his machine (outside the repo) — covers your role and how to collaborate with you. Ask Will if you want to see it.
- `feedback_github_pr_workflow.md` — main is protected, never push
- `feedback_bridge_approval.md` — never move money without explicit OK
- `feedback_destructive_action_consent.md` — pause before anything destructive
- `feedback_no_sybil_advice.md` — never tell miners how to Sybil

### Build & infra
- `feedback_msys2_build.md` — Windows build environment
- `feedback_release_build_host.md` — Linux release builds happen on NYC
- `feedback_seed_node_ulimit.md`, `feedback_iptables_vs_ufw.md`, `feedback_seed_externalip.md` — seed node config gotchas
- `feedback_wrapper_restart.md` — kill wrapper FIRST, then node
- `chiavdf-fixes.md` — Windows LLP64 GMP truncation bugs

---

## 8. What's *not* in this doc

- **Code architecture** — read [CLAUDE.md](../CLAUDE.md) and `src/`. Bitcoin Core's docs are also relevant since we forked it.
- **The Bitcoin Core port plan in detail** — that lives in [`.claude/contracts/`](../.claude/contracts/) and the autonomous queue in [`.claude/autonomous/`](../.claude/autonomous/).
- **DilV-specific consensus details** — see `src/consensus/` and the `dilv_*.md` memory files.
- **Bridge contracts** — see `bridge/` (separate repo) and `bridge_phase8.md`.

If something seems missing, grep `MEMORY.md` first — there's usually a memory file for it.

---

## 9. How to add to this stack yourself

When you find yourself doing the same thing twice:

1. **A recurring task?** Write a skill: `mkdir .claude/skills/my-skill && touch .claude/skills/my-skill/SKILL.md`. Frontmatter is `name`, `description`, `argument-hint`. Body is just a prompt to Claude. Existing skills are good templates.
2. **A complex one-off?** Write a shell script in `scripts/`. Date-stamp if it's a one-off, leave undated if recurring.
3. **A lesson learned?** Tell Claude to save a feedback memory. Don't add it to CLAUDE.md unless you want it injected globally on every session.
4. **A command you keep typing?** Add to `snippets.md`.
5. **A project-state change?** Update `CURRENT_STATE.md` immediately and bump the *Last verified* date.

---

## 10. The catch

A lot of this stuff has accumulated over months and some of it has rotted. If a script has a date in its name (e.g. `health-check-2025-11-07.sh`) and we haven't talked about it recently, it's probably stale. The undated ones are the live tools. When in doubt: open the script, read the first 20 lines, decide. The `/repo-audit` skill is built specifically to help spot this.

If you find something that looks broken or outdated, ping me before fixing — sometimes the apparent staleness is intentional (kept around for a known future need). But mostly it's just cruft.

---

That's everything. Easier to remember the categories than the specifics:

- **Skills** in `.claude/skills/` — slash commands for recurring tasks
- **Python** in `memory/` and `scripts/` — analysis and search
- **Hooks** in `.claude/` — auto-run on events
- **Memory** in `~/.claude/projects/.../memory/` — accumulated knowledge
- **Shell scripts** in `scripts/` — operational runbooks

Welcome aboard. Ask anything.
