# Email Triage Process Guide

This document explains how the Gmail email triage system categorizes and organizes your emails.

## Overview

The triage process analyzes incoming emails and categorizes them into three priority levels:
- **High Priority** - Needs immediate attention
- **Medium Priority** - FYI / Review when available
- **Low Priority** - Can be archived automatically

## How Emails Are Categorized

### High Priority

An email is marked **High Priority** if it matches ANY of these conditions:

| Condition | Examples |
|-----------|----------|
| Sender matches `high_priority.senders` | boss@company.com, client@important.com |
| Subject/body contains `high_priority.keywords` | "verification code", "urgent", "invoice", "payment due", "deadline" |
| Special conditions | is_reply_to_me, is_direct_recipient, is_marked_important |

### Low Priority

An email is marked **Low Priority** if it matches ANY of these conditions:

| Condition | Examples |
|-----------|----------|
| Sender matches `low_priority.senders` | *@amex.com, noreply@*, marketing@* |
| Subject/body contains `low_priority.keywords` | "promotion", "special offer", "sale", "discount" |
| Gmail category is promotions or social | Emails auto-categorized by Gmail |
| **Rarely engaged sender** | Sender's engagement score < 20% |

### Medium Priority

All other emails default to **Medium Priority**.

## Sender Engagement Metrics

The `analyze-senders` command scans your email history to calculate engagement scores.

### Engagement Score Formula

```
engagement_score = (read_rate × 0.7) + (reply_rate × 0.3)
```

- **Read rate**: Percentage of emails from this sender that you've read
- **Reply rate**: Whether you've ever replied to this sender
- Read rate is weighted higher (70%) as it's the primary engagement signal
- Reply rate (30%) boosts senders you actively correspond with

### Example Calculations

| Sender | Read Rate | Reply Rate | Engagement Score |
|--------|-----------|------------|------------------|
| Read all, replied | 100% | 100% | 0.7 + 0.3 = **1.0 (100%)** |
| Read all, no reply | 100% | 0% | 0.7 + 0 = **0.7 (70%)** |
| Read half, no reply | 50% | 0% | 0.35 + 0 = **0.35 (35%)** |
| Never read | 0% | 0% | 0 + 0 = **0.0 (0%)** |

### Rarely Engaged Threshold

Default threshold: **20%** (configurable in `email_rules.yaml`)

- Engagement score < 20% → Sender is "rarely engaged" → Low Priority
- Engagement score >= 20% → Not considered rarely engaged

### Unknown Senders

If a sender is not found in the metrics (new sender), they are **NOT** marked as rarely engaged. They will be categorized based on other rules only.

## Actions Taken After Triage

| Priority | Label Applied | Inbox Status | Other Actions |
|----------|---------------|--------------|---------------|
| High | `⭐ NeedsAttention` | Kept in inbox | Marked important |
| Medium | `📋 FYI` | Kept in inbox | None |
| Low | `🔽 LowPriority` | **Archived** (removed from inbox) | None |

### What "Archived" Means

- Email is removed from your inbox
- Email is NOT deleted - it remains in "All Mail"
- Email retains the `🔽 LowPriority` label for easy finding
- You can still search for and access these emails anytime

## Commands

### Analyze Sender Engagement

```bash
/gmail analyze-senders          # Analyze last 180 days (default)
/gmail analyze-senders 365      # Analyze last year
```

- Scans received emails to calculate engagement per sender/domain
- Saves results to `sender_metrics.json`
- Run periodically (weekly/monthly) to keep metrics current

### Run Email Triage

```bash
/gmail triage                   # Process last 7 days (default)
/gmail triage 14                # Process last 14 days
```

- Categorizes emails based on rules in `email_rules.yaml`
- Uses sender metrics if available
- Applies labels and archives low priority emails

## Configuration

Edit `~/.claude/skills/gmail/email_rules.yaml` to customize:

```yaml
settings:
  days_to_process: 7              # How many days of email to triage
  rarely_opened_threshold: 20     # Engagement threshold (0-100)
  dry_run: false                  # Set true to preview without changes
  only_unread: false              # Set true to only process unread

high_priority:
  senders:
    - "boss@company.com"
    - "*@important-domain.com"
  keywords:
    - "urgent"
    - "verification code"

low_priority:
  senders:
    - "noreply@*"
    - "marketing@*"
  keywords:
    - "unsubscribe"
    - "promotion"
  categories:
    - promotions
    - social
  conditions:
    - rarely_opened_sender        # Uses engagement metrics
```

## Files

| File | Purpose |
|------|---------|
| `gmail_manager.py` | Main script with all commands |
| `email_rules.yaml` | Categorization rules (editable) |
| `sender_metrics.json` | Engagement data (auto-generated) |
| `sender_metrics.json.bak` | Backup of previous metrics |

## Recommended Workflow

1. **Initial Setup**: Run `analyze-senders` to build engagement metrics
2. **Test First**: Set `dry_run: true` in email_rules.yaml, run `triage`, review output
3. **Apply**: Set `dry_run: false`, run `triage` to apply changes
4. **Maintain**: Re-run `analyze-senders` weekly/monthly to update metrics
