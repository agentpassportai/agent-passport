# Agent Passport Lite

**OAuth for the agentic era** — consent-gating for ALL sensitive agent actions.

## 30-Second Setup

```bash
# Initialize and register your agent
./mandate-ledger.sh init agent:my-assistant "Your Name" "personal assistant" "openclaw"

# Grant dev tool access (git, npm, docker, etc.)
./mandate-ledger.sh create-from-template dev-tools

# That's it! The agent will now check permissions before sensitive actions.
```

> **Templates available:** `dev-tools` · `email-team <domain>` · `file-ops <path>` · `web-research`
> Run `./mandate-ledger.sh templates` to see all options.

## The Problem

AI agents need autonomy to be useful, but users need control to trust them.

Current approaches fail:
- **OS permissions** — too coarse (all files or none)
- **OAuth scopes** — static, no caps, no audit trail
- **Tool allowlists** — binary allow/deny, no nuance

Users hold back from granting agent autonomy because they can't constrain it.

## The Solution

**Agent Passport** provides dynamic, auditable, revocable mandates:

```
"I authorize [AGENT] to [ACTION] with [CONSTRAINTS] until [EXPIRY]"
```

Not just for purchases — for **all sensitive actions**:

| Category | What it covers |
|----------|----------------|
| 💳 **Financial** | Purchases, transfers, subscriptions |
| 📧 **Communication** | Emails, messages, tweets, posts |
| 🗑️ **Data** | Delete files, edit documents, database writes |
| ⚙️ **System** | Shell commands, package installs, configs |
| 🔌 **External API** | Third-party API calls with side effects |
| 👤 **Identity** | Public actions "as" the user |

Each mandate includes:
- **Scope constraints** — what targets are allowed
- **Caps/limits** — spending caps, rate limits
- **TTL** — automatic expiry
- **Audit trail** — what happened, when, under which mandate
- **Revocation** — instant stop

## Quick Example

```bash
# Create a mandate allowing email to company domain
./mandate-ledger.sh create '{
  "action_type": "communication",
  "agent_id": "agent:seb",
  "scope": {
    "allowlist": ["*@mycompany.com"],
    "rate_limit": "20/day"
  },
  "ttl": "2026-02-13T00:00:00Z"
}'

# Agent checks before sending
./mandate-ledger.sh check-action "agent:seb" "communication" "bob@mycompany.com"
# {"authorized": true, "mandate_id": "mandate_xxx"}

# After sending, log it
./mandate-ledger.sh log-action "mandate_xxx" 1 "Email to bob@mycompany.com"

# User can see everything
./mandate-ledger.sh audit
./mandate-ledger.sh summary
```

## User Experience

### Granting Permission
```
Agent: I'd like to help organize your inbox. This requires:
       📧 Send emails to your team (max 20/day)
       📄 Read your calendar
       
       [Approve for 7 days] [Customize] [Deny]
```

### Transparent Operation
```
Agent: Sent meeting reminder to sarah@company.com
       ✓ Within mandate: communication/email
       ✓ Recipient in allowlist
       ✓ 3/20 daily limit used
```

### Audit Trail
```
$ ./mandate-ledger.sh audit

📋 Recent actions:
  09:14 - Email sent to team@company.com (meeting notes)
  11:30 - Email sent to sarah@company.com (reminder)
  14:22 - Email BLOCKED to external@gmail.com (not in allowlist)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User                                 │
│   "Send emails to my team, max 20/day, for 7 days"         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Agent Passport                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Mandates   │  │    Audit    │  │     KYA     │         │
│  │   Ledger    │  │    Trail    │  │  Registry   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   check →     │ │   check →     │ │   check →     │
│   ALLOW       │ │   ALLOW       │ │   DENY        │
│   log action  │ │   log action  │ │   (blocked)   │
│               │ │               │ │               │
│ team@co.com   │ │ sarah@co.com  │ │ ext@gmail.com │
└───────────────┘ └───────────────┘ └───────────────┘
```

## Modes

1. **Local** (default) — Fully offline, mandates in `~/.openclaw/agent-passport/`
2. **Preview** — Validation only, no storage
3. **Live (roadmap)** — Future connection to Agent Bridge for multi-agent sync (not yet implemented)

## Commands

```bash
# Mandates
create <json>              # Create mandate
get <mandate_id>           # Get by ID
list [filter]              # List (all|active|revoked|<action_type>)
revoke <mandate_id> [why]  # Revoke

# Authorization
check-action <agent> <type> <target> [amount]
log-action <mandate_id> <amount> [description]

# Audit
audit [limit]              # Recent entries
audit-mandate <id>         # For specific mandate
audit-summary [since]      # By action type
summary                    # Overall stats
export                     # Full JSON backup

# KYA (Know Your Agent)
kya-register <agent_id> <principal> <scope> [provider]
kya-get <agent_id>
kya-list
kya-revoke <agent_id> [why]
```

## Agent Bridge (Coming Soon)

Local mode is the free tier. [Agent Bridge](https://agentbridge.dev) adds:

- **Multi-agent coordination** — prevent conflicting mandates
- **Cross-device sync** — same mandates on laptop/phone/server
- **Organization policies** — IT guardrails for enterprise
- **Compliance reporting** — audit exports for regulated industries
- **Merchant registry** — verified vendors, trust scores
- **Insurance integration** — mandates as proof of authorized scope

## Installation

Already included with OpenClaw. Just enable local mode:

```bash
export AGENT_PASSPORT_LOCAL_LEDGER=true
```

Or in OpenClaw config:
```json
{
  "skills": {
    "entries": {
      "agent-passport-lite": {
        "env": {
          "AGENT_PASSPORT_LOCAL_LEDGER": "true"
        }
      }
    }
  }
}
```

## Why This Matters

**Trust is the bottleneck for agent adoption.**

Users want autonomous agents but fear giving them power. Agent Passport provides the missing middle ground:

- Not "do whatever" — constrained by mandate
- Not "ask every time" — pre-authorized within scope
- Full visibility — audit trail for accountability
- Instant off-switch — revoke anytime

**Agent Passport is how humans stay in control of increasingly capable agents.**

---

Built for [OpenClaw](https://openclaw.ai) | Upgrade to [Agent Bridge](https://agentbridge.dev)
