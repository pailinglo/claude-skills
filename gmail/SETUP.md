# Gmail Skill Setup Guide

This skill allows you to manage your Gmail inbox by cleaning promotional emails, archiving old messages, and more.

## Prerequisites

Install required Python packages:

```bash
pip3 install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

## Gmail API Setup

### 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select an existing one)
   - Click "Select a project" → "New Project"
   - Enter a project name (e.g., "Gmail Manager")
   - Click "Create"

### 2. Enable Gmail API

1. In the Google Cloud Console, go to "APIs & Services" → "Library"
2. Search for "Gmail API"
3. Click on "Gmail API" and click "Enable"

### 3. Create OAuth 2.0 Credentials

1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth client ID"
3. If prompted, configure the OAuth consent screen:
   - User Type: Select "External" (unless you have a Google Workspace)
   - App name: Enter "Gmail Manager" or similar
   - User support email: Your email
   - Developer contact: Your email
   - Click "Save and Continue"
   - Scopes: Skip this step (click "Save and Continue")
   - Test users: Add your Gmail address
   - Click "Save and Continue"
4. Back to creating OAuth client ID:
   - Application type: Select "Desktop app"
   - Name: "Gmail Manager Client"
   - Click "Create"
5. Download the credentials JSON file

### 4. Install Credentials

1. Create the credentials directory:
   ```bash
   mkdir -p ~/.gmail_credentials
   ```

2. Move the downloaded JSON file to the credentials directory:
   ```bash
   mv ~/Downloads/client_secret_*.json ~/.gmail_credentials/credentials.json
   ```

   (Replace the filename with your actual downloaded file)

### 5. First Run - Authorization

The first time you use the skill, it will:
1. Open your browser for OAuth authorization
2. Ask you to sign in to your Google account
3. Request permission to manage your Gmail
4. Save the authorization token for future use

## Usage

Once set up, you can use these commands:

```bash
# Delete promotional emails older than 30 days
/gmail clean-promotions

# Delete promotional emails older than 60 days
/gmail clean-promotions 60

# Delete social emails older than 30 days
/gmail clean-social

# Delete update emails older than 30 days
/gmail clean-updates

# Archive read emails older than 90 days
/gmail archive-read

# Archive read emails older than 180 days
/gmail archive-read 180

# List old unread emails
/gmail list-old-unread

# Show help
/gmail help
```

## Email Categories

Gmail automatically categorizes emails:
- **Promotions**: Marketing emails, offers, deals
- **Social**: Social media notifications, friend requests
- **Updates**: Receipts, bills, statements, confirmations

## Safety Notes

- The skill uses batch operations for faster processing
- Deleted emails go to Trash (recoverable for 30 days)
- Archived emails are removed from Inbox but kept in All Mail
- The skill only requests necessary permissions (gmail.modify scope)
- Your credentials are stored locally in `~/.gmail_credentials/`

## Troubleshooting

**"Missing required packages" error:**
```bash
pip3 install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

**"Credentials not found" error:**
- Ensure credentials.json is in `~/.gmail_credentials/`
- Check the file is named exactly `credentials.json`

**"Access blocked" during OAuth:**
- Make sure you added yourself as a test user in OAuth consent screen
- Your app might need verification for production use (not needed for personal use)

**Token expired:**
- Delete `~/.gmail_credentials/token.pickle`
- Run the command again to re-authorize

## Security

- Never share your `credentials.json` or `token.pickle` files
- The skill runs locally and doesn't send data anywhere except to Google's Gmail API
- You can revoke access anytime at https://myaccount.google.com/permissions
