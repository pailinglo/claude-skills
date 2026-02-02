#!/bin/bash

# Daily Gmail Triage Script
# Runs triage on emails from the last 1 day

LOG_FILE="$HOME/.claude/skills/gmail/triage.log"
SCRIPT_DIR="$HOME/.claude/skills/gmail"

echo "========================================" >> "$LOG_FILE"
echo "Triage started at $(date)" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

cd "$SCRIPT_DIR"

# Run triage for emails from the last 1 day
/usr/bin/python3 gmail_manager.py triage 1 >> "$LOG_FILE" 2>&1

echo "Triage completed at $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"
