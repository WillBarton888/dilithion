# Claude / Claude Code Setup — How Will Has It Configured

**Audience:** Cockatoo, just starting with Claude Code.
**Purpose:** Show you the guard rails and scaffolding I've built up so you can pick the bits you want and skip the bits you don't.
**Date:** 2026-05-01

This is not "the right way to use Claude." It's how I've evolved my setup over ~6 months of using Claude Code daily on a production crypto project. A lot of it is scar tissue — rules added because Claude did something stupid once and I didn't want it to happen again. Take what's useful.

---

## The mental model

Claude Code has three layers of configuration that compound:

1. **Global instructions** — `~/.claude/CLAUDE.md`. Applies to every project on this machine. Where the "how I want Claude to behave" rules live.
2. **Auto-memory** — `~/.claude/projects/<project>/memory/`. A growing index of project-specific facts, lessons, and feedback rules. Claude reads these at session start.
3. **Project config** — `<project>/.claude/`. Settings, hooks, custom skills, mode files. Specific to one repo.

The trick is: **don't put everything in CLAUDE.md.** That file gets injected into every session and competes for context. Keep CLAUDE.md to durable rules; push project-specific facts into memory; push automation into hooks.

---

## Layer 1 — Global rules (`~/.claude/CLAUDE.md`)

This is the file that shapes Claude's defaults across all my work. The big sections (in priority order):

### Session memory protocol
Tells Claude: at the start of every session, read `memory/CURRENT_STATE.md` first, then `recent_sessions.md`, then topic-specific files. **And** — verify state from live sources (RPC, grep, git log) before quoting anything older than 7 days as fact. The "verify-before-assert" rule has saved me multiple times from Claude confidently quoting stale heights or stale incident status.

### Critical data protection
A blunt rule: **never delete `wallet.dat` or any wallet file without explicit permission.** Even with explicit permission, ask once more. Claude is mostly good about this anyway, but the explicit rule means I can trust the safety even when I'm tired.

### Pre-flight check
For any task I give Claude, it must explicitly answer:
- Is this >2 hours of work? → use Plan agent first
- >3 distinct phases? → use Plan agent
- Searching for files/patterns repeatedly? → use Explore agent
- Stuck on env >5 minutes? → delegate to general-purpose agent

This stops Claude from charging in on a complex task without thinking. The "blocking rule" — `for any task >1 hour I am FORBIDDEN from starting direct execution` — is deliberately strong language, because softer wording got ignored.

### Debugging protocol (15/30/60 minute time-boxes)
- 15 min: minimal reproduction
- 30 min: binary search to the exact failing line
- 60 min: HARD STOP, escalate to me

The example in the file is honest about what *not* to do:
> ❌ What I did: Assumed DLLs/antivirus (3 days, $100 of API spend)
> ✅ What I should have done: Remove `if exist` check (5 min). Test (2 min). Fixed in 7 min total.

That paragraph is in there because I want Claude to read it and feel the cost of speculative fixes. Hasn't fully cured the behaviour but reduced it noticeably.

### Step-back principle
"Before any fix: what is the simplest possible 1-line change?" 1-line fix = do it. 10-line = pause. 50+ = STOP and ask if there's a simpler way. This catches Claude's tendency to add new tracking/maps/abstractions when an existing counter would have done the job.

### Project-specific operations
Last ~half of CLAUDE.md is Dilithion-specific: seed-node IPs, RPC command syntax, MSYS2 build commands, release SOP, log verification protocol. **This is the bit I'd cut** if I were starting fresh — most of it would belong in the project's own `.claude/PROJECT.md` rather than global. But it's there because it works.

**Recommendation for you:** start with a much shorter global CLAUDE.md. Just the protocols (session memory, pre-flight, debugging time-boxes, step-back, data protection). Push project facts into the project layer.

---

## Layer 2 — Auto-memory (`~/.claude/projects/<project>/memory/`)

This is the most powerful and least-talked-about part of my setup. Claude has a built-in memory system: it can write small `.md` files into this folder and read them in future sessions. Mine has ~150 files and growing.

### How it's organised

- **`MEMORY.md`** is the index. One line per topic file: `- [Title](file.md) — one-line hook`. Hard cap 200 lines (anything past gets truncated). This file gets auto-injected into every session, so it has to stay tight.
- **`CURRENT_STATE.md`** is the live-state file. Chain heights, active versions, open incidents, last-verified date. Auto-injected on session start. If older than 7 days, Claude refreshes it before relying on it.
- **Topic files** — one per concept. `bridge_phase8.md`, `dilv_sybil_incident.md`, `feedback_no_sybil_advice.md`, etc.

### Four types of memory

1. **`user`** — facts about me (my role, preferences, knowledge level).
2. **`feedback`** — corrections and confirmations. "Don't do X. Why: prior incident. How to apply: when Y." These are the rules I want Claude to follow without me restating them every session.
3. **`project`** — ongoing work, deadlines, decisions, who's doing what. Decays fast.
4. **`reference`** — pointers to external systems. "Bridge issues are in Linear project INGEST."

The convention is **save why, not just what.** A feedback rule without a "Why:" line is brittle — Claude can't judge edge cases. With the why, it can.

### What goes in memory vs CLAUDE.md

- CLAUDE.md = durable rules I want enforced even if I forget about them.
- Memory = project state, lessons, and corrections that accumulate over time.

If I notice Claude making the same mistake twice, I tell it to save a feedback memory. Next session it doesn't make the mistake. Over months this compounds — Claude now does dozens of things correctly that it used to get wrong.

### Verify-before-assert
The single most important rule for memory-driven projects: **memory is point-in-time, not live state.** Before Claude quotes a fact from memory, it has to verify the fact is still true (grep the code, query the RPC, check git log). Stale memory cited as live state has caused incidents.

---

## Layer 3 — Project config (`<project>/.claude/`)

This is where the real machinery lives. My Dilithion `.claude/` folder has:

```
.claude/
├── MODE                  # "manual" or "autonomous" — toggles permission mode
├── PROJECT.md            # Project overview for AI agents
├── settings.json         # Permissions + hooks
├── settings.local.json   # Personal overrides (gitignored)
├── mode.sh               # Switch between manual/autonomous
├── state_refresh.sh      # SessionStart hook — pulls live chain state
├── hooks/
│   ├── autonomous_mode_check.sh   # PreToolUse — blocks dangerous ops in auto mode
│   └── user_prompt_router.sh      # UserPromptSubmit — routes prompt to memory
├── skills/               # ~20 custom slash commands (see below)
├── contracts/            # Acceptance criteria for active tasks
├── plans/                # Plan agent outputs
└── autonomous/           # State for the unattended /autonomous mode
```

### `settings.json` — permissions

Three sections that matter:

```json
{
  "permissions": {
    "allow":  ["Bash", "Read", "Edit", "Write", ...],
    "deny":   [
      "Bash(rm wallet*)",
      "Bash(rm -rf /)",
      "Bash(git push --force main *)",
      ...
    ],
    "defaultMode": "bypassPermissions"
  }
}
```

- **`allow`** is broad patterns, not literal commands. ~25 glob patterns covers ~95% of what Claude needs to do. Don't accumulate 200 literal entries — they get out of sync and you spend more time approving prompts than working.
- **`deny`** is the catastrophic-always list. `rm wallet*`, `rm -rf /`, `git push --force main`. These apply in every mode, including bypass.
- **`defaultMode: bypassPermissions`** means Claude doesn't ask before each tool call. Trades safety for speed. Only safe because the deny list catches the truly dangerous things AND I have hooks that add a second layer (see below).

### Two-mode permission system (`MODE` + hook)

This is my favourite trick. The `.claude/MODE` file contains either `manual` or `autonomous`. A PreToolUse hook reads it on every tool call:

- `MODE=manual` → hook is a no-op. Open bypass.
- `MODE=autonomous` → hook blocks `ssh`, `git push`, `gh release`, package installs, edits to `settings.json` itself, edits to its own rules. A whole class of "production-touching" actions becomes impossible.

I run `bash .claude/mode.sh autonomous` before kicking off an unattended task ("work on this for 8 hours"), and `bash .claude/mode.sh manual` for daily interactive work. Mode swap takes effect on the very next tool call — no restart.

The crucial bit: **the hook can't be bypassed by Claude itself**, because in autonomous mode it can't edit `settings.json` or `.claude/MODE`. So even a misaligned Claude can't loosen its own restrictions.

### Hooks (`hooks/`)

Three hooks, each does one thing well:

1. **`SessionStart` → `state_refresh.sh`** — runs on every session start. SSHes to the production seed node, pulls current block heights, dumps git log, dumps active incidents from `CURRENT_STATE.md`, injects the lot into context. So Claude opens the session knowing the live state, not the state from when memory was last written. ~10 seconds, fails silently.

2. **`UserPromptSubmit` → `user_prompt_router.sh`** — every time I send a prompt, this script greps it for keywords and injects a `<system-reminder>` pointing to relevant memory files. If I mention "bridge", it points Claude at `bridge_phase8.md` and `bridge_relayer_ops.md`. If I mention "MSYS2", it points at the Windows build lessons. **This solves the "Claude has the file but doesn't remember to read it" problem.**

3. **`PreToolUse` → `autonomous_mode_check.sh`** — the autonomous-mode enforcement described above.

### Custom skills (`skills/`)

A skill is a slash command. `~/.claude/skills/<name>/SKILL.md` defines it, and `<project>/.claude/skills/<name>/SKILL.md` overrides per-project. Each skill is a markdown file with frontmatter (name, description, argument hints) followed by a prompt that tells Claude exactly how to do that one thing.

Mine include:
- `/build` — cross-platform build, detects when clean build needed, MSYS2-aware on Windows
- `/node-status` — health check across all seed nodes
- `/deploy` — rolling deploy, enforces 3-nodes-running rule
- `/debug-node` — structured debugging with log freshness verification
- `/release` — full release SOP with binary builds and bootstrap
- `/repo-audit` — scan for cruft
- `/log-tail`, `/peer-manage`, `/test-rpc`, `/mining-report`, `/chain-health`, etc.

The reason these exist: each one captures a recurring task that I used to type out by hand every time, including all the gotchas. `/build` knows that header changes need a clean rebuild. `/deploy` knows to kill the wrapper FIRST before SIGINT. `/release` knows the macOS CI upload step always fails with 403 and needs manual intervention.

A skill is just a prompt with structure. If you find yourself typing the same instructions to Claude repeatedly, write a skill.

---

## Other things I run

### `digest_conversations.py`
Script in the memory folder. After a session ends, run `digest_conversations.py --rebuild` and it summarises recent conversations into `recent_sessions.md`. Means future-me (and future-Claude) can read what happened in the last few sessions in a few hundred lines instead of skimming jsonl logs.

### `/contract <task>` skill
For any moderate-or-complex task, before coding, I run `/contract` and it writes acceptance criteria to `.claude/contracts/active_contract.md`. I review and approve. Claude then ticks boxes as it completes them. Keeps "done" honest.

### `/handoff <phase>` skill
For multi-phase work. After each phase, write a structured handoff to `.claude/handoff.md`. At the start of the next phase, read it. Stops context loss between sessions or after compaction.

---

## What I'd recommend you do (in order)

1. **Start small.** Don't copy all of mine. The ~22KB CLAUDE.md grew over time and most of it earned its place through pain. Yours doesn't need to.

2. **Write a 30-line `~/.claude/CLAUDE.md`** with just:
   - Your role and how you like Claude to communicate
   - "Never delete X without permission" (whatever your X is)
   - "Verify before asserting state from memory"
   - A simple debugging time-box (e.g., 15/30/60)
   - Step-back principle ("simplest possible fix first")

3. **Use the auto-memory.** When Claude does something well, tell it to save a feedback memory. When it does something stupid and you correct it, tell it to save a feedback memory. After a few weeks you'll have a personalised Claude that doesn't repeat its own mistakes.

4. **Add a project `.claude/` folder** with:
   - A `settings.json` with broad-pattern allows and a tight deny list (always-deny the things you'd cry over: production data, force-push to main, wallet files)
   - A `PROJECT.md` describing the project for Claude

5. **Add hooks once you feel friction.** Don't pre-emptively add hooks. Wait until you notice "Claude keeps not knowing X" — then write a hook that injects X. The `user_prompt_router.sh` pattern (keyword-match → point at memory) is high-leverage and a good first hook.

6. **Add the two-mode system if you're going to run unattended work.** If you only ever work interactively, you don't need it. If you ever say "work on this overnight", build the autonomous-mode hook before you do.

7. **Write skills only after the second time you type the same instructions.** Premature skills rot.

---

## What I'd skip

- The Dilithion-specific operational sections in my CLAUDE.md (RPC syntax tables, seed node IPs, release SOP). These belong in project layer, not global.
- The very long `.claude/skills/release/SKILL.md` style — only worth it after you've done the workflow by hand a few times and know the gotchas.
- `/contract` and `/handoff` until you have a task big enough to need them.

---

## Files worth reading in this repo

If you want to see the actual implementations:

- [`.claude/settings.json`](../.claude/settings.json) — permissions + hook wiring
- [`.claude/mode.sh`](../.claude/mode.sh) — mode switcher
- [`.claude/hooks/autonomous_mode_check.sh`](../.claude/hooks/autonomous_mode_check.sh) — PreToolUse enforcement
- [`.claude/hooks/user_prompt_router.sh`](../.claude/hooks/user_prompt_router.sh) — keyword → memory router
- [`.claude/state_refresh.sh`](../.claude/state_refresh.sh) — live state injector
- [`.claude/skills/build/SKILL.md`](../.claude/skills/build/SKILL.md) — example skill

The global `~/.claude/CLAUDE.md` and the `~/.claude/projects/c--Users-will-dilithion/memory/` folder aren't in this repo (they're in my home dir), but happy to share them directly if you want a reference.

---

## TL;DR

- Three layers: global rules, auto-memory, project config.
- CLAUDE.md = durable rules. Memory = accumulated lessons. Hooks = automation.
- Two-mode permission system: open bypass for daily work, locked-down hook for unattended work.
- Skills are reusable prompts for recurring tasks.
- Verify before asserting. Step back before fixing. Time-box debugging.
- Build it incrementally — every rule should earn its place.

Ping me with questions. Most of this is small once you see it; the hard part was deciding *which* rules to add, and that came from doing it wrong first.
