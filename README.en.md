# saas-security-audit

**The security audit your checklist can't run.**

An AI-agent audit for SaaS codebases that covers the usual attack surface (RLS, policies, privilege, webhooks, injection, storage, LLM, privacy) **and a second axis nobody scans for**: the places where your app quietly does the wrong thing to users acting in good faith.

Runs on [Claude Code](https://claude.com/claude-code). Outputs one self-contained HTML report with a single gate: **ready to scale, or not?**

Read-only. It finds, proves and proposes. It never touches your code.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#requirements)
[![Self-test](https://img.shields.io/badge/self--test-19%20detectors-brightgreen.svg)](#quick-start)

```
$ python verificar.py          # real output, Portuguese; glosses added here

[3/4] detectores mecanicos     # mechanical detectors
  ok   rls-ausente = 1                 # a table with no RLS at all
  ok   definer-sem-search-path = 1     # ...and the one WITH search_path is not flagged
  ok   policy-tautologica = 1          # only the real one; neighbours must not be accused
  ok   privilegio-no-frontend = 1      # service-role client imported into a .tsx component
  ...
  ok   recorte de policy nao invade a vizinha
  ok   cobertura provada em 3 universos       # coverage proven across 3 universes

[4/4] painel.py                # report
  ok   exatamente um </script>
  ok   segredo do exemplo nao aparece inteiro no painel
  ok   zero requisicao externa (fonte, script, css)
  ok   gate contou 11 bloqueadores (4 criticos + 7 altos)

APROVADO: scanner, detectores, cobertura e painel funcionam nesta maquina.
```

---

## Why this exists

Every AppSec checklist asks: **what can an attacker do that they shouldn't?** Right question. This tool answers it in full.

But in a small SaaS, the more likely damage comes from somewhere else entirely, and no scanner on the market looks there: **does the system do the right thing for someone acting in good faith?** Nobody attacks. The code is "correct". The security checklist goes green. And the product still breaks:

| What happens | Why the checklist misses it |
|---|---|
| A guard denies access to an entitled user, because it was written assuming "entitled" = "has a paid subscription" | The authorization control is present and working. It's just asking the wrong question |
| Your UI offers a **payment button to someone you invited for free** | Nothing is insecure here. It's a billing path reached by the wrong person |
| A query reads a protected table with the user's client, RLS returns **zero rows with no error**, and zero rows becomes "all clear" | RLS is enabled, the policy is correct, the row filter works. The bug is the *direction* the failure falls in |
| Three code paths write payments and one omits the provider's payment id, so refunds can't find the sale and commission keeps being paid | Every path is authenticated and authorized |
| The app promises a date an external partner won't honor, because the calculation derived from the convenient column | No vulnerability. Just a promise the real world won't keep |

That's **dimension B (correctness)**, with four lenses of its own. It is the part of this project that doesn't exist anywhere else.

## What you get

| | |
|---|---|
| 🔍 **Two dimensions** | A: security and abuse, 9 vulnerability families with severity and refutation criteria. B: correctness, 4 lenses (access matrix, failure direction, write-path consistency, external rule anchor) |
| 📐 **Coverage proven by arithmetic** | A deterministic scanner partitions every table, server function and API route into explicit batches, then **asserts** sum-of-batches == universe and empty intersection. It raises rather than audit by sampling |
| ⚖️ **Adversarial verification** | Independent skeptic agents, clean context, whose only job is to **knock down** each critical and high finding. They may refute *only* by citing the blocker at `file:line` |
| 💸 **Money gets its own batch** | Payment tables never get delegated to a subagent, and are audited on both dimensions |
| 🧩 **The access matrix is never sliced** | The bug lives in the crossing between a guard and an access type. Splitting it hides exactly what it exists to find |
| 📊 **Self-contained HTML report** | Zero external requests, opens offline, editable finding status that persists, schema heat map, coverage proof, and a "ready to scale?" gate |
| 🌐 **Optional runtime layer** | Feed it a HAR export and it reports the headers actually served, real cookie flags, CORS, caching, and responses over-fetching personal data |
| ✅ **Ships with its own proof** | An example SaaS with one planted defect per detector, and a self-test that verifies all 19 of them plus the report's properties |
| 🔒 **Safe by construction** | Read-only on your repo. No secret value is ever written or printed. Artifacts never land inside the audited repository |

## Honest limits, up front

- **Static and passive.** It does not forge webhooks, probe production, or call functions directly. That's pentesting, and it needs explicit authorization.
- **Not a replacement** for an external pentest or a human security review.
- **The scanner reads migrations**, so it sees what was *requested*, not what's in the database. That's what phase 1 (ground truth) is for.
- **LLM findings can be wrong.** Hence the skeptic, the mandatory `file:line`, and a calibration gate after the very first batch.
- **Passing the gate is not a certification.** It's an informed verdict about what was examined, shipped with the list of what wasn't.

> The method, the prompts and the report are written in **Portuguese**, because they were built for a Brazilian studio and the findings go straight to a human reader. The code, the CLI and the profile format are language-neutral. Translation PRs are very welcome.

---

## What makes it different from "running an audit prompt"

| | Usual approach | Here |
|---|---|---|
| **Coverage** | the agent picks what to look at, and samples without realizing it | a deterministic scanner partitions the universe into batches with explicit lists, and **asserts** that the sum of batches equals the universe with empty intersection |
| **Cheap work** | the model counts policies and greps for `SECURITY DEFINER` | Python scanner, zero LLM, reproducible. Agents only handle what needs judgment |
| **Validation** | the agent that found the issue confirms its own issue | **independent skeptics, clean context, trying to knock down every serious finding**, allowed to refute only by citing the blocker at `file:line` |
| **Severity** | everything is critical | critical requires a concrete exploitation path. Missing hardening is never critical |
| **Honesty** | "your app is secure" | the audit declares what it did **not** see. Without a HAR, the runtime layer is marked unverified |

## Requirements

- **Python 3.11+** (uses `tomllib`). No external dependencies: standard library only.
- **Claude Code** (the skill becomes the `/auditor` command) or **Codex** (read `AGENTS.md`, same method in its own format). Any runner with subagents works. The scanner and the dashboard run standalone, with no AI at all.
- Optional: the **Supabase MCP** to pull real database state (advisors, schema), and a **HAR** exported from the running app.

## Stack calibration

The engine is calibrated for **Supabase (Postgres + RLS + PostgREST) + TypeScript + payment webhook + serverless deploy**. The profile's `padrao_servidor` covers `tanstack-start`, `next-app`, `supabase-edge` and `api-propria`, and the template ships glob recipes for each.

On a different stack (Rails, Django, Laravel, Go), **both dimensions and the catalogs still apply**, but the mechanical detectors find less: they read SQL migrations and TypeScript. There the audit runs through the prompts, with the scanner acting as a partial inventory. This is stated up front on purpose.

## Quick start

```bash
git clone https://github.com/thdamas/saas-security-audit.git
cd saas-security-audit

# 1. Prove it works on this machine: runs against the bundled example app,
#    which has one planted defect per detector.
python verificar.py

# 2. Run it and open the dashboard
python scanner.py --perfil exemplo/.claude/auditoria/perfil.toml --saida ./saida --print
python painel.py --pasta ./saida/exemplo-assinatura/*-completa --abrir
```

`verificar.py` checks 19 detectors, the measured inventory, the coverage proof and 5 properties of the dashboard. If it prints `APROVADO`, you're good.

### On your own app

```bash
python scanner.py --descobrir /path/to/your/app          # draft the path globs
cp referencias/perfil.template.toml /path/to/your/app/.claude/auditoria/perfil.toml
python scanner.py --perfil /path/to/your/app/.claude/auditoria/perfil.toml --print
```

Then copy `SKILL.md` (plus `prompts/` and `referencias/`) into `.claude/skills/auditor/` and invoke `/auditor` inside Claude Code. The skill runs a 6-phase loop with a human gate between phases.

> **The profile is the cheapest and most dangerous failure point.** A wrong role or a missing folder makes the whole audit report confidently about the wrong place.

## How it works

```
Phase 0  Profile        the app map, approved by a human
Phase 1  Ground truth   REAL database state (advisors, schema, buckets, cron)
Phase 2  Mechanical     scanner.py: inventory + detection + proven partition
Phase 3  Batch 01       calibration gate: one batch, you check the output shape
Phase 4  Fan-out        one subagent per batch; money and access matrix stay with the orchestrator
Phase 5  Skeptics       different agents trying to KNOCK DOWN every critical and high
Phase 6  Dashboard      painel.py: self-contained HTML, "ready to scale?" gate
```

Two batches are never delegated: **money**, because that's where mistakes cost directly, and the **access matrix**, because the bug lives in the crossing between a guard and an access type, so slicing it hides exactly what it exists to find.

## Process safety

An audit produces the most sensitive document a project will ever have.

- Artifacts **never** land inside the audited repository. Default: `~/saas-security-audit/auditorias/`. The scanner warns if you point the output inside the repo.
- **No secret value** is ever written or printed: type, file and line only. The dashboard masks again before writing HTML.
- **HAR only from a test account.** A real session HAR carries a live token and real personal data.
- The only file the audit writes into your app is `perfil.toml`.

## License and credit

Apache-2.0. Built by **[ALQUIM_IA.LAB](https://alquimialab.com.br)** (Thiago Menezes Damasceno).

PRs welcome: new detectors, recipes for other stacks, or a correctness lens you learned the hard way.
