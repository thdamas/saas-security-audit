# saas-security-audit

AI-agent security and **correctness** audit for a SaaS, with coverage proven by arithmetic and adversarial verification of every serious finding. Runs on [Claude Code](https://claude.com/claude-code) and outputs a self-contained HTML dashboard with one simple gate: **ready to scale or not?**

Read-only: it finds, proves and proposes. It never fixes anything on its own.

> The method, the prompts and the dashboard are written in **Portuguese**, because they were built for a Brazilian studio and the findings go straight to a human reader. The code, the profile format and this page are the part you need to operate it. Translation PRs are welcome.

---

## The problem it attacks

Every application security checklist asks the same question: **what can an attacker do that they shouldn't?** That is the right question, and this tool covers it fully (RLS, policies, privilege, webhooks, injection, storage, LLM, privacy).

But a small SaaS has a second axis, a more likely one, that no checklist covers: **does the system do the right thing for someone acting in good faith?** Nobody attacks, and the system breaks on its own.

- It denies access to someone entitled to it, because the guard was written assuming "entitled" = "has a paid subscription".
- It offers a payment button to someone you invited for free.
- It reads a protected table with the wrong client, RLS returns **zero rows with no error**, and zero rows becomes "everything is fine".
- It writes payments through three different paths and one of them forgets the provider's payment id, so refunds can't find the sale.
- It promises a date an external partner won't honor, because the code derived it from the convenient column instead of the real one.

This axis doesn't require anyone to be interested in attacking you. It only requires someone to have written a condition thinking about the main case. Here it's called **dimension B (correctness)**, with four lenses of its own.

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
- **Claude Code**, or any agent runner with subagents, for the judgment phases. The scanner and the dashboard run standalone, with no AI at all.
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

## Limits, stated plainly

- **Static and passive analysis.** It does not forge webhooks, probe production, or call functions directly. That's pentesting, and it needs explicit authorization.
- **Not a replacement** for an external pentest or human security review.
- **The scanner reads migrations**, so it sees what was requested, not what's in the database. That's why phase 1 exists.
- **LLM findings can be wrong.** Hence the skeptic, the mandatory `file:line`, and the calibration gate.
- Passing the gate **is not a certification**. It's an informed verdict about what was examined, with a list of what wasn't.

## License and credit

Apache-2.0. Built by **[ALQUIM_IA.LAB](https://alquimialab.com.br)** (Thiago Menezes Damasceno).

PRs welcome: new detectors, recipes for other stacks, or a correctness lens you learned the hard way.
