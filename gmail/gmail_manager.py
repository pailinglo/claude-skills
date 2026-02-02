#!/usr/bin/env python3
"""
Gmail Manager - Clean and organize Gmail emails
"""

import os
import sys
import pickle
import yaml
import fnmatch
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("❌ Missing required packages. Please install:")
    print("   pip3 install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib")
    sys.exit(1)

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Credentials directory
CREDS_DIR = Path.home() / '.gmail_credentials'
TOKEN_FILE = CREDS_DIR / 'token.pickle'
CREDENTIALS_FILE = CREDS_DIR / 'credentials.json'

# Sender metrics file
METRICS_FILE = Path(__file__).parent / 'sender_metrics.json'


def get_gmail_service():
    """Authenticate and return Gmail API service."""
    creds = None

    # Load existing credentials
    if TOKEN_FILE.exists():
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)

    # Refresh or get new credentials
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not CREDENTIALS_FILE.exists():
                print("❌ Gmail API credentials not found!")
                print("\nSetup instructions:")
                print("1. Go to https://console.cloud.google.com/")
                print("2. Create a new project or select existing one")
                print("3. Enable Gmail API")
                print("4. Create OAuth 2.0 credentials (Desktop app)")
                print(f"5. Download credentials and save to: {CREDENTIALS_FILE}")
                print(f"\nCreate directory: mkdir -p {CREDS_DIR}")
                sys.exit(1)

            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_FILE), SCOPES)
            creds = flow.run_local_server(port=0)

        # Save credentials
        CREDS_DIR.mkdir(parents=True, exist_ok=True)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)


def get_cutoff_date(days):
    """Calculate cutoff date for email age."""
    cutoff = datetime.now() - timedelta(days=days)
    return cutoff.strftime('%Y/%m/%d')


def extract_sender_email(from_header):
    """Parse 'Name <email@domain.com>' to get just the email address."""
    if not from_header:
        return ''
    # Try to extract email from angle brackets
    match = re.search(r'<([^>]+)>', from_header)
    if match:
        return match.group(1).lower()
    # If no angle brackets, assume the whole thing is an email
    return from_header.strip().lower()


def get_domain(email):
    """Extract domain from email address."""
    if not email or '@' not in email:
        return ''
    return email.split('@')[-1].lower()


# Cache for user's email address
_user_email_cache = None


def get_user_email(service):
    """Get the authenticated user's email address."""
    global _user_email_cache
    if _user_email_cache:
        return _user_email_cache

    try:
        profile = service.users().getProfile(userId='me').execute()
        _user_email_cache = profile.get('emailAddress', '').lower()
        return _user_email_cache
    except HttpError as error:
        print(f'❌ Error getting user profile: {error}')
        return ''


def is_cc_recipient(email, user_email):
    """Check if user is CC'd (not primary recipient).

    Args:
        email: Email details dict with 'to' and 'cc' fields
        user_email: The authenticated user's email address

    Returns:
        True if user is in CC field, False otherwise
    """
    if not user_email:
        return False

    cc_field = email.get('cc', '')
    if not cc_field:
        return False

    # Extract all email addresses from CC field
    # CC can be comma-separated: "Name1 <email1>, Name2 <email2>"
    cc_emails = []
    for part in cc_field.split(','):
        extracted = extract_sender_email(part.strip())
        if extracted:
            cc_emails.append(extracted.lower())

    return user_email.lower() in cc_emails


def is_marked_important(email):
    """Check if Gmail has marked the email as important.

    Args:
        email: Email details dict with 'labels' field

    Returns:
        True if IMPORTANT label is present, False otherwise
    """
    return 'IMPORTANT' in email.get('labels', [])


def is_reply_to_me(service, email, user_email):
    """Check if email is a reply in a thread the user participated in.

    This checks if:
    1. The email has In-Reply-To header (indicating it's a reply)
    2. The thread contains messages sent by the user

    Args:
        service: Gmail API service
        email: Email details dict
        user_email: The authenticated user's email address

    Returns:
        True if email is a reply to something the user sent, False otherwise
    """
    if not user_email:
        return False

    # Check if email has In-Reply-To header (indicates it's a reply)
    headers = email.get('headers', {})
    in_reply_to = headers.get('in-reply-to', '')
    references = headers.get('references', '')

    # If no reply headers, it's not a reply - fast exit
    if not in_reply_to and not references:
        return False

    # Get the thread to check if we participated
    try:
        # Get thread ID from the email
        msg = service.users().messages().get(
            userId='me',
            id=email['id'],
            format='minimal'
        ).execute()

        thread_id = msg.get('threadId')
        if not thread_id:
            return False

        # Get all messages in the thread
        thread = service.users().threads().get(
            userId='me',
            id=thread_id,
            format='metadata',
            metadataHeaders=['From']
        ).execute()

        messages = thread.get('messages', [])

        # Check if any message in thread was sent by us
        for msg in messages:
            # Skip the current email
            if msg['id'] == email['id']:
                continue

            # Check if message is from us (has SENT label)
            if 'SENT' in msg.get('labelIds', []):
                return True

            # Also check From header
            for header in msg.get('payload', {}).get('headers', []):
                if header['name'].lower() == 'from':
                    from_email = extract_sender_email(header['value'])
                    if from_email.lower() == user_email.lower():
                        return True

        return False

    except HttpError:
        return False


def calculate_engagement_score(read_rate, reply_rate):
    """Compute weighted engagement score."""
    return (read_rate * 0.7) + (reply_rate * 0.3)


def save_sender_metrics(metrics):
    """Save metrics to JSON file with backup of previous version."""
    temp_file = METRICS_FILE.with_suffix('.json.tmp')
    backup_file = METRICS_FILE.with_suffix('.json.bak')

    # Step 1: Write to temporary file first
    try:
        with open(temp_file, 'w') as f:
            json.dump(metrics, f, indent=2)
    except Exception as e:
        print(f"❌ Failed to write metrics: {e}")
        if temp_file.exists():
            temp_file.unlink()
        raise

    # Step 2: Back up existing file (if exists)
    if METRICS_FILE.exists():
        try:
            if backup_file.exists():
                backup_file.unlink()
            METRICS_FILE.rename(backup_file)
            print(f"📦 Previous metrics backed up to {backup_file.name}")
        except Exception as e:
            print(f"⚠️  Could not backup old metrics: {e}")

    # Step 3: Rename temp to final (atomic on most systems)
    try:
        temp_file.rename(METRICS_FILE)
        print(f"📁 Saved metrics to {METRICS_FILE}")
    except Exception as e:
        print(f"❌ Failed to finalize metrics file: {e}")
        # Try to restore backup
        if backup_file.exists() and not METRICS_FILE.exists():
            backup_file.rename(METRICS_FILE)
            print("↩️  Restored previous metrics from backup")
        raise


def load_sender_metrics():
    """Load cached metrics from JSON file."""
    if not METRICS_FILE.exists():
        return None
    try:
        with open(METRICS_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def is_rarely_engaged_sender(email_from, metrics, threshold):
    """Check if sender's engagement is below threshold.

    Args:
        email_from: The From header of the email
        metrics: The loaded sender metrics dict
        threshold: Engagement threshold (0-100)

    Returns:
        True if sender is rarely engaged with, False otherwise
    """
    if not metrics:
        return False

    sender_email = extract_sender_email(email_from)
    domain = get_domain(sender_email)
    threshold_decimal = threshold / 100.0

    # Check sender-specific metrics first
    senders = metrics.get('senders', {})
    if sender_email in senders:
        score = senders[sender_email].get('engagement_score', 1.0)
        return score < threshold_decimal

    # Fall back to domain metrics
    domains = metrics.get('domains', {})
    if domain in domains:
        score = domains[domain].get('engagement_score', 1.0)
        return score < threshold_decimal

    # Unknown sender - don't mark as rarely engaged
    return False


def search_emails(service, query):
    """Search for emails matching the query."""
    try:
        results = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=500
        ).execute()

        messages = results.get('messages', [])

        # Handle pagination for large results
        while 'nextPageToken' in results:
            page_token = results['nextPageToken']
            results = service.users().messages().list(
                userId='me',
                q=query,
                pageToken=page_token,
                maxResults=500
            ).execute()
            messages.extend(results.get('messages', []))

        return messages
    except HttpError as error:
        print(f'❌ Error searching emails: {error}')
        return []


def delete_messages(service, message_ids):
    """Move messages to trash."""
    if not message_ids:
        return 0

    deleted = 0
    total = len(message_ids)

    for i, msg_id in enumerate(message_ids):
        try:
            service.users().messages().trash(
                userId='me',
                id=msg_id
            ).execute()
            deleted += 1

            # Progress indicator every 100 messages
            if (i + 1) % 100 == 0:
                print(f'⏳ Progress: {i + 1}/{total} emails processed...')

        except HttpError as error:
            if 'timeout' in str(error).lower():
                print(f'⚠️  Timeout on message {i + 1}, continuing...')
                continue
            print(f'❌ Error trashing message: {error}')
        except Exception as error:
            if 'timeout' in str(error).lower():
                print(f'⚠️  Timeout on message {i + 1}, continuing...')
                continue
            print(f'❌ Unexpected error: {error}')

    return deleted


def archive_messages(service, message_ids):
    """Archive multiple messages (remove from inbox)."""
    if not message_ids:
        return 0

    archived = 0

    for msg_id in message_ids:
        try:
            service.users().messages().modify(
                userId='me',
                id=msg_id,
                body={'removeLabelIds': ['INBOX']}
            ).execute()
            archived += 1
        except HttpError as error:
            print(f'❌ Error archiving message: {error}')

    return archived


def clean_promotions(service, days):
    """Delete promotional emails older than specified days."""
    cutoff = get_cutoff_date(days)
    query = f'category:promotions before:{cutoff}'

    print(f"🔍 Searching for promotional emails older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print("✅ No promotional emails found to delete.")
        return

    print(f"📧 Found {len(messages)} promotional emails")
    message_ids = [msg['id'] for msg in messages]

    deleted = delete_messages(service, message_ids)
    print(f"🗑️  Deleted {deleted} promotional emails")


def clean_social(service, days):
    """Delete social emails older than specified days."""
    cutoff = get_cutoff_date(days)
    query = f'category:social before:{cutoff}'

    print(f"🔍 Searching for social emails older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print("✅ No social emails found to delete.")
        return

    print(f"📧 Found {len(messages)} social emails")
    message_ids = [msg['id'] for msg in messages]

    deleted = delete_messages(service, message_ids)
    print(f"🗑️  Deleted {deleted} social emails")


def clean_updates(service, days):
    """Delete update emails older than specified days."""
    cutoff = get_cutoff_date(days)
    query = f'category:updates before:{cutoff}'

    print(f"🔍 Searching for update emails older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print("✅ No update emails found to delete.")
        return

    print(f"📧 Found {len(messages)} update emails")
    message_ids = [msg['id'] for msg in messages]

    deleted = delete_messages(service, message_ids)
    print(f"🗑️  Deleted {deleted} update emails")


def archive_read(service, days):
    """Archive read emails older than specified days."""
    cutoff = get_cutoff_date(days)
    query = f'is:read in:inbox before:{cutoff}'

    print(f"🔍 Searching for read emails in inbox older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print("✅ No read emails found to archive.")
        return

    print(f"📧 Found {len(messages)} read emails")
    message_ids = [msg['id'] for msg in messages]

    archived = archive_messages(service, message_ids)
    print(f"📦 Archived {archived} read emails")


def list_old_unread(service, days):
    """List unread emails older than specified days."""
    cutoff = get_cutoff_date(days)
    query = f'is:unread before:{cutoff}'

    print(f"🔍 Searching for unread emails older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print("✅ No old unread emails found.")
        return

    print(f"📧 Found {len(messages)} old unread emails")

    # Get details for first 10 messages
    print("\nShowing first 10:")
    for msg in messages[:10]:
        try:
            msg_detail = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='metadata',
                metadataHeaders=['From', 'Subject', 'Date']
            ).execute()

            headers = {h['name']: h['value'] for h in msg_detail['payload']['headers']}
            print(f"  • From: {headers.get('From', 'Unknown')}")
            print(f"    Subject: {headers.get('Subject', 'No subject')}")
            print(f"    Date: {headers.get('Date', 'Unknown')}")
            print()
        except HttpError as error:
            print(f'❌ Error getting message details: {error}')


def get_label_id(service, label_name):
    """Get label ID by name. Returns None if not found."""
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        for label in labels:
            if label['name'] == label_name:
                return label['id']

        return None
    except HttpError as error:
        print(f'❌ Error getting labels: {error}')
        return None


def list_labels(service):
    """List all Gmail labels."""
    print("🏷️  Your Gmail Labels:\n")

    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        # Separate system labels from user labels
        system_labels = []
        user_labels = []

        for label in labels:
            if label['type'] == 'system':
                system_labels.append(label['name'])
            else:
                user_labels.append(label['name'])

        if user_labels:
            print("📁 Custom Labels:")
            for name in sorted(user_labels):
                print(f"   • {name}")

        print("\n📂 System Labels:")
        for name in sorted(system_labels):
            print(f"   • {name}")

        print(f"\n📊 Total: {len(user_labels)} custom, {len(system_labels)} system labels")

    except HttpError as error:
        print(f'❌ Error listing labels: {error}')


def archive_by_label(service, label_name, days):
    """Archive emails with a specific label older than specified days."""
    # Verify label exists
    label_id = get_label_id(service, label_name)

    if not label_id:
        print(f"❌ Label '{label_name}' not found.")
        print("💡 Run '/gmail list-labels' to see available labels.")
        return

    cutoff = get_cutoff_date(days)
    # Use label name in query (with quotes for labels containing spaces/special chars)
    query = f'label:"{label_name}" before:{cutoff}'

    print(f"🔍 Searching for emails with label '{label_name}' older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print(f"✅ No emails found with label '{label_name}' older than {days} days.")
        return

    print(f"📧 Found {len(messages)} emails")
    message_ids = [msg['id'] for msg in messages]

    archived = archive_messages(service, message_ids)
    print(f"📦 Archived {archived} emails with label '{label_name}'")


def delete_by_label(service, label_name, days):
    """Delete (trash) emails with a specific label older than specified days."""
    # Verify label exists
    label_id = get_label_id(service, label_name)

    if not label_id:
        print(f"❌ Label '{label_name}' not found.")
        print("💡 Run '/gmail list-labels' to see available labels.")
        return

    cutoff = get_cutoff_date(days)
    # Use label name in query (with quotes for labels containing spaces/special chars)
    query = f'label:"{label_name}" before:{cutoff}'

    print(f"🔍 Searching for emails with label '{label_name}' older than {days} days...")
    messages = search_emails(service, query)

    if not messages:
        print(f"✅ No emails found with label '{label_name}' older than {days} days.")
        return

    print(f"📧 Found {len(messages)} emails")
    message_ids = [msg['id'] for msg in messages]

    deleted = delete_messages(service, message_ids)
    print(f"🗑️  Deleted {deleted} emails with label '{label_name}'")


def analyze_sender_engagement(service, days=180):
    """Scan emails and compute engagement metrics per sender/domain.

    Args:
        service: Gmail API service
        days: Number of days to analyze (default 180)
    """
    print(f"📊 Analyzing sender engagement for the last {days} days...")

    # Step 1: Get all received emails (exclude sent and drafts)
    print("🔍 Fetching received emails...")
    query = f'newer_than:{days}d -in:sent -in:drafts'
    received_messages = search_emails(service, query)
    print(f"  Found {len(received_messages)} received emails")

    # Step 2: Get all sent emails (to find replies)
    print("🔍 Fetching sent emails...")
    sent_query = f'newer_than:{days}d in:sent'
    sent_messages = search_emails(service, sent_query)
    print(f"  Found {len(sent_messages)} sent emails")

    # Build a set of message IDs we've replied to
    print("🔍 Analyzing replies...")
    replied_to_senders = set()

    for i, msg in enumerate(sent_messages):
        try:
            msg_detail = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='metadata',
                metadataHeaders=['In-Reply-To', 'References', 'To']
            ).execute()

            headers = {h['name'].lower(): h['value'] for h in msg_detail['payload']['headers']}

            # If this sent email has In-Reply-To, it's a reply
            if headers.get('in-reply-to') or headers.get('references'):
                to_header = headers.get('to', '')
                to_email = extract_sender_email(to_header)
                if to_email:
                    replied_to_senders.add(to_email)

            if (i + 1) % 100 == 0:
                print(f"  Processed {i + 1}/{len(sent_messages)} sent emails...")

        except HttpError:
            continue

    print(f"  Found replies to {len(replied_to_senders)} unique senders")

    # Step 3: Analyze received emails
    print("📧 Analyzing received emails...")
    sender_stats = {}  # email -> {total, read, replied}
    domain_stats = {}  # domain -> {total, read, replied}

    for i, msg in enumerate(received_messages):
        try:
            msg_detail = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='metadata',
                metadataHeaders=['From', 'Date']
            ).execute()

            headers = {h['name'].lower(): h['value'] for h in msg_detail['payload']['headers']}
            labels = msg_detail.get('labelIds', [])

            from_header = headers.get('from', '')
            sender_email = extract_sender_email(from_header)
            domain = get_domain(sender_email)
            date_str = headers.get('date', '')

            if not sender_email:
                continue

            # Check if email is read (UNREAD label not present)
            is_read = 'UNREAD' not in labels

            # Check if we've replied to this sender
            has_replied = sender_email in replied_to_senders

            # Update sender stats
            if sender_email not in sender_stats:
                sender_stats[sender_email] = {
                    'total': 0, 'read': 0, 'replied': 0, 'last_received': ''
                }
            sender_stats[sender_email]['total'] += 1
            if is_read:
                sender_stats[sender_email]['read'] += 1
            if has_replied:
                sender_stats[sender_email]['replied'] = 1  # Binary: did we ever reply?
            if date_str:
                sender_stats[sender_email]['last_received'] = date_str

            # Update domain stats
            if domain:
                if domain not in domain_stats:
                    domain_stats[domain] = {'total': 0, 'read': 0, 'replied': 0}
                domain_stats[domain]['total'] += 1
                if is_read:
                    domain_stats[domain]['read'] += 1
                if has_replied:
                    domain_stats[domain]['replied'] += 1

            if (i + 1) % 100 == 0:
                print(f"  Processed {i + 1}/{len(received_messages)} received emails...")

        except HttpError:
            continue

    # Step 4: Calculate engagement scores
    print("📈 Calculating engagement scores...")

    senders_output = {}
    for email, stats in sender_stats.items():
        total = stats['total']
        read = stats['read']
        replied = stats['replied']

        read_rate = read / total if total > 0 else 0
        reply_rate = replied / total if total > 0 else 0
        engagement_score = calculate_engagement_score(read_rate, reply_rate)

        senders_output[email] = {
            'total': total,
            'read': read,
            'replied': replied,
            'read_rate': round(read_rate, 3),
            'reply_rate': round(reply_rate, 3),
            'engagement_score': round(engagement_score, 3),
            'last_received': stats['last_received']
        }

    domains_output = {}
    for domain, stats in domain_stats.items():
        total = stats['total']
        read = stats['read']
        replied = stats['replied']

        read_rate = read / total if total > 0 else 0
        reply_rate = replied / total if total > 0 else 0
        engagement_score = calculate_engagement_score(read_rate, reply_rate)

        domains_output[domain] = {
            'total': total,
            'read': read,
            'replied': replied,
            'read_rate': round(read_rate, 3),
            'reply_rate': round(reply_rate, 3),
            'engagement_score': round(engagement_score, 3)
        }

    # Step 5: Save metrics
    metrics = {
        'generated_at': datetime.now().isoformat(),
        'analysis_period_days': days,
        'total_emails_analyzed': len(received_messages),
        'senders': senders_output,
        'domains': domains_output
    }

    save_sender_metrics(metrics)

    # Step 6: Print summary
    print(f"\n📊 Engagement Analysis Summary:")
    print(f"  Total emails analyzed: {len(received_messages)}")
    print(f"  Unique senders: {len(senders_output)}")
    print(f"  Unique domains: {len(domains_output)}")

    # Find rarely engaged senders (< 20% engagement)
    rarely_engaged = [
        (email, data['engagement_score'], data['total'])
        for email, data in senders_output.items()
        if data['engagement_score'] < 0.2 and data['total'] >= 3
    ]
    rarely_engaged.sort(key=lambda x: x[1])

    if rarely_engaged:
        print(f"\n🔽 Top rarely engaged senders (score < 0.2, 3+ emails):")
        for email, score, total in rarely_engaged[:10]:
            print(f"    {email}: {score:.1%} ({total} emails)")

    # Find highly engaged senders
    highly_engaged = [
        (email, data['engagement_score'], data['total'])
        for email, data in senders_output.items()
        if data['engagement_score'] >= 0.8 and data['total'] >= 3
    ]
    highly_engaged.sort(key=lambda x: -x[1])

    if highly_engaged:
        print(f"\n⭐ Top highly engaged senders (score >= 0.8, 3+ emails):")
        for email, score, total in highly_engaged[:10]:
            print(f"    {email}: {score:.1%} ({total} emails)")

    print(f"\n✅ Analysis complete! Metrics saved to sender_metrics.json")
    print("💡 Tip: Run '/gmail triage' to apply engagement-based categorization")


def load_rules():
    """Load email categorization rules from YAML file."""
    rules_file = Path(__file__).parent / 'email_rules.yaml'

    if not rules_file.exists():
        print(f"❌ Rules file not found: {rules_file}")
        print("Please create email_rules.yaml with your categorization rules.")
        sys.exit(1)

    with open(rules_file, 'r') as f:
        return yaml.safe_load(f)


def get_email_details(service, msg_id):
    """Get full email details including headers and body."""
    try:
        msg = service.users().messages().get(
            userId='me',
            id=msg_id,
            format='full'
        ).execute()

        headers = {}
        for header in msg['payload']['headers']:
            headers[header['name'].lower()] = header['value']

        return {
            'id': msg_id,
            'headers': headers,
            'labels': msg.get('labelIds', []),
            'snippet': msg.get('snippet', ''),
            'from': headers.get('from', ''),
            'to': headers.get('to', ''),
            'cc': headers.get('cc', ''),
            'subject': headers.get('subject', ''),
        }
    except HttpError as error:
        print(f'❌ Error getting email details: {error}')
        return None


def matches_sender(email_from, sender_patterns):
    """Check if email sender matches any pattern.

    Extracts the email address from the From header before matching.
    Supports patterns like: "user@domain.com", "*@domain.com", "user@*"
    """
    # Extract just the email address from "Name <email@domain.com>" format
    sender_email = extract_sender_email(email_from)

    for pattern in sender_patterns:
        # Match against extracted email address
        if fnmatch.fnmatch(sender_email.lower(), pattern.lower()):
            return True
        # Also match against full From header for backwards compatibility
        if fnmatch.fnmatch(email_from.lower(), pattern.lower()):
            return True
    return False


def matches_keywords(text, keywords):
    """Check if text contains any keywords."""
    text_lower = text.lower()
    for keyword in keywords:
        if keyword.lower() in text_lower:
            return True
    return False


def get_or_create_label(service, label_name):
    """Get label ID or create if it doesn't exist."""
    try:
        # List all labels
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        # Check if label exists
        for label in labels:
            if label['name'] == label_name:
                return label['id']

        # Create new label
        label_object = {
            'name': label_name,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'
        }
        created_label = service.users().labels().create(
            userId='me',
            body=label_object
        ).execute()

        print(f"✨ Created new label: {label_name}")
        return created_label['id']

    except HttpError as error:
        print(f'❌ Error with label: {error}')
        return None


def apply_email_action(service, msg_id, action_config, label_name, dry_run=False):
    """Apply configured action to an email."""
    if dry_run:
        action_desc = []
        if action_config.get('keep_in_inbox'):
            action_desc.append('keep in inbox')
        else:
            action_desc.append('archive')
        if action_config.get('mark_important'):
            action_desc.append('mark important')
        if action_config.get('star'):
            action_desc.append('star')
        print(f"    Would apply label '{label_name}' and {', '.join(action_desc)}")
        return True

    try:
        label_id = get_or_create_label(service, label_name)
        if not label_id:
            return False

        # Add label
        add_labels = [label_id]
        remove_labels = []

        # Handle inbox
        if not action_config.get('keep_in_inbox', True):
            remove_labels.append('INBOX')

        # Handle important
        if action_config.get('mark_important', False):
            add_labels.append('IMPORTANT')

        # Handle star
        if action_config.get('star', False):
            add_labels.append('STARRED')

        # Apply changes
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={
                'addLabelIds': add_labels,
                'removeLabelIds': remove_labels
            }
        ).execute()

        return True

    except HttpError as error:
        print(f'❌ Error applying action: {error}')
        return False


def categorize_email(email, rules, metrics=None, rarely_opened_threshold=20, user_email=None, service=None):
    """Determine the category for an email based on rules.

    Args:
        email: Email details dict
        rules: Categorization rules from YAML
        metrics: Sender engagement metrics (optional)
        rarely_opened_threshold: Threshold for rarely engaged senders (0-100)
        user_email: The authenticated user's email address (for CC checking)
        service: Gmail API service (for thread checking in is_reply_to_me)
    """
    subject_and_snippet = f"{email['subject']} {email['snippet']}"

    # Check high priority
    high = rules.get('high_priority', {})
    if high.get('senders') and matches_sender(email['from'], high['senders']):
        return 'high_priority'
    if high.get('keywords') and matches_keywords(subject_and_snippet, high['keywords']):
        return 'high_priority'

    # Check high priority conditions
    high_conditions = high.get('conditions', [])
    if 'is_marked_important' in high_conditions:
        if is_marked_important(email):
            return 'high_priority'
    if 'is_reply_to_me' in high_conditions and service and user_email:
        if is_reply_to_me(service, email, user_email):
            return 'high_priority'

    # Check medium priority senders FIRST (before low priority checks)
    # This ensures explicitly listed senders take precedence over Gmail categories
    medium = rules.get('medium_priority', {})
    if medium.get('senders') and matches_sender(email['from'], medium['senders']):
        return 'medium_priority'

    # Check low priority
    low = rules.get('low_priority', {})
    if low.get('senders') and matches_sender(email['from'], low['senders']):
        return 'low_priority'
    if low.get('keywords') and matches_keywords(subject_and_snippet, low['keywords']):
        return 'low_priority'
    # Check if email is in promotional or social category
    if 'CATEGORY_PROMOTIONS' in email['labels'] or 'CATEGORY_SOCIAL' in email['labels']:
        categories = low.get('categories', [])
        if 'promotions' in categories or 'social' in categories:
            return 'low_priority'

    # Check for rarely engaged sender condition
    low_conditions = low.get('conditions', [])
    if 'rarely_opened_sender' in low_conditions and metrics:
        if is_rarely_engaged_sender(email['from'], metrics, rarely_opened_threshold):
            return 'low_priority'

    # Check medium priority conditions (is_cc_recipient)
    medium_conditions = medium.get('conditions', [])
    if 'is_cc_recipient' in medium_conditions and user_email:
        if is_cc_recipient(email, user_email):
            return 'medium_priority'

    # Check medium priority keywords
    if medium.get('keywords') and matches_keywords(subject_and_snippet, medium['keywords']):
        return 'medium_priority'

    # Default to medium priority if no rules match
    return 'medium_priority'


def triage_emails(service, days=None, start_date=None, end_date=None):
    """Categorize and organize emails based on rules.

    Args:
        service: Gmail API service
        days: Number of days to look back (default: 7)
        start_date: Start date in YYYY/MM/DD format (optional)
        end_date: End date in YYYY/MM/DD format (optional)
    """
    print("📋 Loading email categorization rules...")
    rules = load_rules()

    settings = rules.get('settings', {})
    days_to_process = days if days else settings.get('days_to_process', 7)
    dry_run = settings.get('dry_run', False)
    only_unread = settings.get('only_unread', False)
    rarely_opened_threshold = settings.get('rarely_opened_threshold', 20)

    # Load sender engagement metrics
    metrics = load_sender_metrics()
    if metrics:
        print(f"📊 Loaded sender engagement metrics (analyzed {metrics.get('total_emails_analyzed', 0)} emails)")
    else:
        print("📊 No sender metrics found. Run '/gmail analyze-senders' to enable engagement-based categorization.")

    # Get user's email address for CC checking
    user_email = get_user_email(service)
    if user_email:
        print(f"👤 User email: {user_email}")

    if dry_run:
        print("🔍 DRY RUN MODE - No changes will be made\n")

    # Build query based on date parameters
    if start_date and end_date:
        query_parts = [f'after:{start_date}', f'before:{end_date}']
        print(f"🔍 Searching emails from {start_date} to {end_date}...")
    elif start_date:
        query_parts = [f'after:{start_date}']
        print(f"🔍 Searching emails after {start_date}...")
    else:
        query_parts = [f'newer_than:{days_to_process}d']
        print(f"🔍 Searching for emails from last {days_to_process} days...")

    if only_unread:
        query_parts.append('is:unread')
    query = ' '.join(query_parts)

    messages = search_emails(service, query)

    if not messages:
        print("✅ No emails found to categorize.")
        return

    print(f"📧 Found {len(messages)} emails to process\n")

    # Categorize emails
    categorized = {'high_priority': [], 'medium_priority': [], 'low_priority': []}

    print("🤖 Analyzing emails...")
    for i, msg in enumerate(messages):
        email = get_email_details(service, msg['id'])
        if not email:
            continue

        category = categorize_email(email, rules, metrics, rarely_opened_threshold, user_email, service)
        categorized[category].append(email)

        # Progress indicator
        if (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(messages)} emails...")

    print(f"\n📊 Categorization Results:")
    print(f"  ⭐ High Priority: {len(categorized['high_priority'])} emails")
    print(f"  📋 Medium Priority: {len(categorized['medium_priority'])} emails")
    print(f"  🔽 Low Priority: {len(categorized['low_priority'])} emails\n")

    # Apply actions
    actions = rules.get('actions', {})

    for category, emails in categorized.items():
        if not emails:
            continue

        action_config = actions.get(category, {})
        label_name = action_config.get('label', category)

        print(f"🏷️  Applying '{label_name}' to {len(emails)} emails...")

        for i, email in enumerate(emails):
            if dry_run:
                if i < 3:  # Show first 3 examples in dry run
                    print(f"  📧 From: {email['from']}")
                    print(f"     Subject: {email['subject']}")
                    apply_email_action(service, email['id'], action_config, label_name, dry_run=True)
                elif i == 3:
                    print(f"  ... and {len(emails) - 3} more")
            else:
                apply_email_action(service, email['id'], action_config, label_name, dry_run=False)
                if (i + 1) % 50 == 0:
                    print(f"  Progress: {i + 1}/{len(emails)} emails...")

        print(f"  ✅ Completed {category}\n")

    if dry_run:
        print("💡 Tip: Set 'dry_run: false' in email_rules.yaml to apply changes")
    else:
        print("✅ Email triage completed!")


def show_help():
    """Display help information."""
    print("Gmail Manager - Available Commands:")
    print("\n📋 Email Organization:")
    print("  /gmail triage [days]                  - Categorize emails by priority (default: 7 days)")
    print("  /gmail triage START_DATE [END_DATE]   - Categorize emails in date range (YYYY/MM/DD)")
    print("  /gmail analyze-senders [days]         - Analyze sender engagement (default: 180 days)")
    print("\n📧 Email Cleanup by Category:")
    print("  /gmail clean-promotions [days]  - Delete promotional emails (default: 30 days)")
    print("  /gmail clean-social [days]      - Delete social emails (default: 30 days)")
    print("  /gmail clean-updates [days]     - Delete update emails (default: 30 days)")
    print("  /gmail archive-read [days]      - Archive read emails (default: 90 days)")
    print("  /gmail list-old-unread [days]   - List unread emails (default: 30 days)")
    print("\n🏷️  Email Cleanup by Label:")
    print("  /gmail list-labels                    - Show all your Gmail labels")
    print("  /gmail archive-label LABEL [days]     - Archive emails with label (default: 7 days)")
    print("  /gmail delete-label LABEL [days]      - Delete emails with label (default: 7 days)")
    print("\n📖 Help:")
    print("  /gmail help                     - Show this help message")
    print("\nExamples:")
    print("  /gmail triage                   - Categorize emails from last 7 days")
    print("  /gmail triage 14                - Categorize emails from last 14 days")
    print("  /gmail triage 2024/01/01        - Categorize all emails after Jan 1, 2024")
    print("  /gmail triage 2024/01/01 2024/06/30  - Categorize emails from Jan 1 to Jun 30, 2024")
    print("  /gmail analyze-senders          - Analyze engagement for last 6 months")
    print("  /gmail analyze-senders 365      - Analyze engagement for last year")
    print("  /gmail clean-promotions         - Delete promotions older than 30 days")
    print("  /gmail clean-promotions 60      - Delete promotions older than 60 days")
    print("  /gmail archive-read 180         - Archive read emails older than 6 months")
    print("  /gmail list-labels              - Show all available labels")
    print('  /gmail archive-label "🔽 LowPriority" 3   - Archive LowPriority emails older than 3 days')
    print('  /gmail delete-label "🔽 LowPriority" 7    - Delete LowPriority emails older than 7 days')
    print('  /gmail archive-label "📋 FYI" 14          - Archive FYI emails older than 14 days')
    print("\n💡 Tips:")
    print("  - Run 'analyze-senders' periodically to update engagement metrics")
    print("  - Edit email_rules.yaml to customize triage rules")
    print("  - Set 'dry_run: true' in rules to preview changes without applying them")
    print("  - Use 'list-labels' to see exact label names for cleanup commands")


def main():
    """Main entry point."""
    if len(sys.argv) < 2 or sys.argv[1] in ['help', '--help', '-h']:
        show_help()
        return

    operation = sys.argv[1]

    try:
        service = get_gmail_service()

        # Handle list-labels (no additional arguments)
        if operation == 'list-labels':
            list_labels(service)
            return

        # Handle triage with date range support
        if operation == 'triage':
            if len(sys.argv) == 2:
                # Default: 7 days
                triage_emails(service, days=7)
            elif len(sys.argv) > 2 and '/' in sys.argv[2]:
                # Date range mode (YYYY/MM/DD format detected)
                start_date = sys.argv[2]
                end_date = sys.argv[3] if len(sys.argv) > 3 else None
                triage_emails(service, start_date=start_date, end_date=end_date)
            else:
                # Days mode
                days = int(sys.argv[2])
                triage_emails(service, days=days)
            return

        # Handle archive-label and delete-label (require label name)
        if operation in ['archive-label', 'delete-label']:
            if len(sys.argv) < 3:
                print(f"❌ Missing label name for {operation}")
                print(f"Usage: /gmail {operation} LABEL_NAME [days]")
                print("💡 Run '/gmail list-labels' to see available labels.")
                return

            label_name = sys.argv[2]
            days = int(sys.argv[3]) if len(sys.argv) > 3 else 7  # Default 7 days

            if operation == 'archive-label':
                archive_by_label(service, label_name, days)
            else:
                delete_by_label(service, label_name, days)
            return

        # Handle other operations with days parameter
        days = int(sys.argv[2]) if len(sys.argv) > 2 else None

        # Set default days based on operation
        if days is None:
            if operation == 'archive-read':
                days = 90
            elif operation == 'analyze-senders':
                days = 180
            else:
                days = 30

        operations = {
            'analyze-senders': analyze_sender_engagement,
            'clean-promotions': clean_promotions,
            'clean-social': clean_social,
            'clean-updates': clean_updates,
            'archive-read': archive_read,
            'list-old-unread': list_old_unread,
        }

        if operation not in operations:
            print(f"❌ Unknown operation: {operation}")
            show_help()
            return

        operations[operation](service, days)

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
