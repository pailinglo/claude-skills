---
name: gmail
description: Manage Gmail emails - triage, clean by category or label, archive old messages
---

When the user invokes /gmail:

1. Parse $ARGUMENTS to determine the operation:

   **Email Organization:**
   - `triage [days]` - Categorize emails by priority and apply labels (default: 7 days)
   - `triage START_DATE [END_DATE]` - Triage emails in date range (YYYY/MM/DD)
   - `analyze-senders [days]` - Analyze sender engagement metrics (default: 180 days)

   **Cleanup by Category:**
   - `clean-promotions [days]` - Delete promotional emails older than N days (default: 30)
   - `clean-social [days]` - Delete social emails older than N days (default: 30)
   - `clean-updates [days]` - Delete update emails older than N days (default: 30)
   - `archive-read [days]` - Archive read emails older than N days (default: 90)
   - `list-old-unread [days]` - List unread emails older than N days (default: 30)

   **Cleanup by Label:**
   - `list-labels` - Show all Gmail labels
   - `archive-label LABEL [days]` - Archive emails with label older than N days (default: 7)
   - `delete-label LABEL [days]` - Delete emails with label older than N days (default: 7)

   - No arguments or `help` - Show available commands

2. Run the Python script: `python3 gmail_manager.py <operation> [arguments]`

3. The script handles:
   - Gmail API authentication (OAuth2)
   - Searching emails by category, label, and date
   - Triaging and labeling emails by priority
   - Deleting or archiving emails
   - Providing summary of actions taken

4. Display results:
   - Number of emails processed
   - Categories/labels affected
   - Any errors encountered

Setup requirements:
- First-time use requires Gmail API credentials setup
- Script will guide user through OAuth2 authentication
- Credentials stored securely in ~/.gmail_credentials/

Keep responses concise and show clear summaries of actions taken.
