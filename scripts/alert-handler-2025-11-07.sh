#!/bin/bash
# Dilithion Mainnet Node - Alert Handler Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/alert-handler-2025-11-07.sh --check            # Run health check and alert if issues
#   ./scripts/alert-handler-2025-11-07.sh --alert "message"  # Send specific alert
#   ./scripts/alert-handler-2025-11-07.sh --test             # Test alert delivery
#
# Cron usage (check every 5 minutes):
#   */5 * * * * /path/to/scripts/alert-handler-2025-11-07.sh --check
#
# Version: 1.0.0
# Created: 2025-11-07

set -e  # Exit on error

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-11-07"

# Alert configuration file (optional)
CONFIG_FILE="$HOME/.dilithion/alert-config.conf"

# Alert channels (enable/disable as needed)
ALERT_EMAIL_ENABLED=false
ALERT_SLACK_ENABLED=false
ALERT_DISCORD_ENABLED=false
ALERT_TELEGRAM_ENABLED=false
ALERT_PUSHOVER_ENABLED=false
ALERT_LOG_ENABLED=true

# Email configuration
EMAIL_TO=""
EMAIL_FROM=""
EMAIL_SMTP_SERVER=""
EMAIL_SMTP_PORT="587"

# Slack configuration
SLACK_WEBHOOK_URL=""

# Discord configuration
DISCORD_WEBHOOK_URL=""

# Telegram configuration
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

# Pushover configuration
PUSHOVER_USER_KEY=""
PUSHOVER_API_TOKEN=""

# Alert log file
ALERT_LOG_FILE="$HOME/.dilithion/alerts.log"

# Alert rate limiting (prevent alert spam)
ALERT_COOLDOWN=300  # 5 minutes between repeated alerts for same issue
ALERT_STATE_DIR="$HOME/.dilithion/alert-state"

# Alert severity levels
SEVERITY_INFO="INFO"
SEVERITY_WARNING="WARNING"
SEVERITY_ERROR="ERROR"
SEVERITY_CRITICAL="CRITICAL"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==============================================================================
# Helper Functions
# ==============================================================================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Load configuration file
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        print_info "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    fi
}

# Initialize alert state directory
init_alert_state() {
    mkdir -p "$ALERT_STATE_DIR"
}

# Check if alert should be rate-limited
should_rate_limit() {
    local alert_key="$1"
    local state_file="$ALERT_STATE_DIR/${alert_key}.last"

    if [ -f "$state_file" ]; then
        local last_alert_time=$(cat "$state_file")
        local current_time=$(date +%s)
        local time_diff=$((current_time - last_alert_time))

        if [ "$time_diff" -lt "$ALERT_COOLDOWN" ]; then
            print_info "Alert rate-limited (cooldown: ${ALERT_COOLDOWN}s, remaining: $((ALERT_COOLDOWN - time_diff))s)"
            return 0  # Yes, rate limit
        fi
    fi

    # Update last alert time
    echo "$(date +%s)" > "$state_file"
    return 1  # No, don't rate limit
}

# ==============================================================================
# Alert Delivery Methods
# ==============================================================================

# Send email alert
send_email_alert() {
    local subject="$1"
    local message="$2"
    local severity="$3"

    if [ "$ALERT_EMAIL_ENABLED" != true ]; then
        return 0
    fi

    if [ -z "$EMAIL_TO" ] || [ -z "$EMAIL_FROM" ]; then
        print_warning "Email alerts enabled but not configured"
        return 1
    fi

    print_info "Sending email alert to $EMAIL_TO..."

    # Use mail command if available
    if command -v mail &> /dev/null; then
        echo "$message" | mail -s "[$severity] $subject" "$EMAIL_TO"
        print_success "Email sent"
    elif command -v sendmail &> /dev/null; then
        (
            echo "Subject: [$severity] $subject"
            echo "From: $EMAIL_FROM"
            echo "To: $EMAIL_TO"
            echo ""
            echo "$message"
        ) | sendmail "$EMAIL_TO"
        print_success "Email sent via sendmail"
    else
        print_warning "No email client available (install mailutils or sendmail)"
        return 1
    fi
}

# Send Slack alert
send_slack_alert() {
    local subject="$1"
    local message="$2"
    local severity="$3"

    if [ "$ALERT_SLACK_ENABLED" != true ]; then
        return 0
    fi

    if [ -z "$SLACK_WEBHOOK_URL" ]; then
        print_warning "Slack alerts enabled but webhook URL not configured"
        return 1
    fi

    print_info "Sending Slack alert..."

    # Determine color based on severity
    local color="#808080"  # gray
    case "$severity" in
        "$SEVERITY_CRITICAL")
            color="#FF0000"  # red
            ;;
        "$SEVERITY_ERROR")
            color="#FF6600"  # orange
            ;;
        "$SEVERITY_WARNING")
            color="#FFAA00"  # yellow
            ;;
        "$SEVERITY_INFO")
            color="#00AA00"  # green
            ;;
    esac

    local payload=$(cat <<EOF
{
  "attachments": [
    {
      "color": "$color",
      "title": "[$severity] $subject",
      "text": "$message",
      "footer": "Dilithion Alert",
      "ts": $(date +%s)
    }
  ]
}
EOF
)

    curl -s -X POST "$SLACK_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null

    if [ $? -eq 0 ]; then
        print_success "Slack alert sent"
    else
        print_error "Failed to send Slack alert"
        return 1
    fi
}

# Send Discord alert
send_discord_alert() {
    local subject="$1"
    local message="$2"
    local severity="$3"

    if [ "$ALERT_DISCORD_ENABLED" != true ]; then
        return 0
    fi

    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
        print_warning "Discord alerts enabled but webhook URL not configured"
        return 1
    fi

    print_info "Sending Discord alert..."

    # Determine color based on severity
    local color=8421504  # gray
    case "$severity" in
        "$SEVERITY_CRITICAL")
            color=16711680  # red
            ;;
        "$SEVERITY_ERROR")
            color=16737280  # orange
            ;;
        "$SEVERITY_WARNING")
            color=16755200  # yellow
            ;;
        "$SEVERITY_INFO")
            color=43520  # green
            ;;
    esac

    local payload=$(cat <<EOF
{
  "embeds": [
    {
      "title": "[$severity] $subject",
      "description": "$message",
      "color": $color,
      "footer": {
        "text": "Dilithion Alert"
      },
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
    }
  ]
}
EOF
)

    curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null

    if [ $? -eq 0 ]; then
        print_success "Discord alert sent"
    else
        print_error "Failed to send Discord alert"
        return 1
    fi
}

# Send Telegram alert
send_telegram_alert() {
    local subject="$1"
    local message="$2"
    local severity="$3"

    if [ "$ALERT_TELEGRAM_ENABLED" != true ]; then
        return 0
    fi

    if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
        print_warning "Telegram alerts enabled but not configured"
        return 1
    fi

    print_info "Sending Telegram alert..."

    local full_message="*[$severity] $subject*

$message

_Dilithion Alert - $(date '+%Y-%m-%d %H:%M:%S')_"

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${full_message}" \
        -d "parse_mode=Markdown" > /dev/null

    if [ $? -eq 0 ]; then
        print_success "Telegram alert sent"
    else
        print_error "Failed to send Telegram alert"
        return 1
    fi
}

# Send Pushover alert
send_pushover_alert() {
    local subject="$1"
    local message="$2"
    local severity="$3"

    if [ "$ALERT_PUSHOVER_ENABLED" != true ]; then
        return 0
    fi

    if [ -z "$PUSHOVER_USER_KEY" ] || [ -z "$PUSHOVER_API_TOKEN" ]; then
        print_warning "Pushover alerts enabled but not configured"
        return 1
    fi

    print_info "Sending Pushover alert..."

    # Determine priority based on severity
    local priority=0  # normal
    case "$severity" in
        "$SEVERITY_CRITICAL")
            priority=2  # emergency
            ;;
        "$SEVERITY_ERROR")
            priority=1  # high
            ;;
    esac

    curl -s -X POST "https://api.pushover.net/1/messages.json" \
        -F "token=$PUSHOVER_API_TOKEN" \
        -F "user=$PUSHOVER_USER_KEY" \
        -F "title=[$severity] $subject" \
        -F "message=$message" \
        -F "priority=$priority" > /dev/null

    if [ $? -eq 0 ]; then
        print_success "Pushover alert sent"
    else
        print_error "Failed to send Pushover alert"
        return 1
    fi
}

# Log alert to file
log_alert() {
    local subject="$1"
    local message="$2"
    local severity="$3"

    if [ "$ALERT_LOG_ENABLED" != true ]; then
        return 0
    fi

    local log_dir=$(dirname "$ALERT_LOG_FILE")
    mkdir -p "$log_dir"

    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$severity] $subject: $message" >> "$ALERT_LOG_FILE"

    print_info "Alert logged to $ALERT_LOG_FILE"
}

# ==============================================================================
# Main Alert Function
# ==============================================================================

send_alert() {
    local subject="$1"
    local message="$2"
    local severity="${3:-$SEVERITY_INFO}"
    local alert_key="${4:-default}"

    # Check rate limiting
    if should_rate_limit "$alert_key"; then
        print_info "Alert suppressed due to rate limiting"
        return 0
    fi

    print_info "Sending alert: [$severity] $subject"

    # Send to all enabled channels
    send_email_alert "$subject" "$message" "$severity" || true
    send_slack_alert "$subject" "$message" "$severity" || true
    send_discord_alert "$subject" "$message" "$severity" || true
    send_telegram_alert "$subject" "$message" "$severity" || true
    send_pushover_alert "$subject" "$message" "$severity" || true
    log_alert "$subject" "$message" "$severity"

    print_success "Alert sent"
}

# ==============================================================================
# Health Check Integration
# ==============================================================================

run_health_check_and_alert() {
    print_info "Running health check..."

    # Run health check script
    SCRIPT_DIR=$(dirname "$0")
    HEALTH_CHECK_SCRIPT="$SCRIPT_DIR/health-check-2025-11-07.sh"

    if [ ! -f "$HEALTH_CHECK_SCRIPT" ]; then
        print_error "Health check script not found: $HEALTH_CHECK_SCRIPT"
        send_alert \
            "Health Check Script Missing" \
            "Cannot run health check: script not found at $HEALTH_CHECK_SCRIPT" \
            "$SEVERITY_ERROR" \
            "health_check_missing"
        exit 1
    fi

    # Run health check and capture result
    HEALTH_CHECK_JSON=$("$HEALTH_CHECK_SCRIPT" --json 2>/dev/null)

    if [ $? -ne 0 ]; then
        send_alert \
            "Health Check Failed" \
            "Health check script failed to run" \
            "$SEVERITY_ERROR" \
            "health_check_failed"
        return 1
    fi

    # Parse JSON result (simple parsing - would benefit from jq)
    NODE_RUNNING=$(echo "$HEALTH_CHECK_JSON" | grep -o '"running":[a-z]*' | cut -d: -f2)
    RPC_ACCESSIBLE=$(echo "$HEALTH_CHECK_JSON" | grep -o '"rpc_accessible":[a-z]*' | cut -d: -f2)
    BLOCK_HEIGHT=$(echo "$HEALTH_CHECK_JSON" | grep -o '"height":[0-9]*' | cut -d: -f2)
    PEER_COUNT=$(echo "$HEALTH_CHECK_JSON" | grep -o '"peer_count":[0-9]*' | cut -d: -f2)
    MINING_ACTIVE=$(echo "$HEALTH_CHECK_JSON" | grep -o '"active":[a-z]*' | cut -d: -f2)
    DISK_AVAILABLE=$(echo "$HEALTH_CHECK_JSON" | grep -o '"disk_available_gb":[0-9]*' | cut -d: -f2)

    # Check for critical issues
    if [ "$NODE_RUNNING" = "false" ]; then
        send_alert \
            "Node Down" \
            "Dilithion node is not running! Immediate action required." \
            "$SEVERITY_CRITICAL" \
            "node_down"
    fi

    if [ "$RPC_ACCESSIBLE" = "false" ] && [ "$NODE_RUNNING" = "true" ]; then
        send_alert \
            "RPC Not Accessible" \
            "Node is running but RPC server is not accessible" \
            "$SEVERITY_ERROR" \
            "rpc_down"
    fi

    if [ -n "$PEER_COUNT" ] && [ "$PEER_COUNT" -lt 3 ]; then
        send_alert \
            "Low Peer Count" \
            "Only $PEER_COUNT peers connected (minimum: 3). Node may not sync properly." \
            "$SEVERITY_WARNING" \
            "low_peers"
    fi

    if [ -n "$DISK_AVAILABLE" ] && [ "$DISK_AVAILABLE" -lt 10 ]; then
        send_alert \
            "Low Disk Space" \
            "Only ${DISK_AVAILABLE}GB disk space remaining (minimum: 10GB)" \
            "$SEVERITY_ERROR" \
            "low_disk"
    fi

    # Check for informational events
    if [ "$MINING_ACTIVE" = "true" ]; then
        # Mining is active - could send daily summary instead of constant alerts
        print_info "Mining is active"
    fi

    print_success "Health check complete"
}

# ==============================================================================
# Test Alert Function
# ==============================================================================

test_alerts() {
    print_info "Testing alert delivery..."

    send_alert \
        "Alert Test" \
        "This is a test alert from Dilithion alert handler. If you received this, alerts are configured correctly." \
        "$SEVERITY_INFO" \
        "test_alert_$(date +%s)"

    print_success "Test alert sent"
}

# ==============================================================================
# Configuration Setup
# ==============================================================================

setup_config() {
    print_info "Setting up alert configuration..."

    echo "This will create a configuration file at: $CONFIG_FILE"
    echo ""

    read -p "Enable email alerts? (y/n): " enable_email
    if [ "$enable_email" = "y" ]; then
        ALERT_EMAIL_ENABLED=true
        read -p "Email address to send alerts to: " EMAIL_TO
        read -p "Email address to send alerts from: " EMAIL_FROM
    fi

    read -p "Enable Slack alerts? (y/n): " enable_slack
    if [ "$enable_slack" = "y" ]; then
        ALERT_SLACK_ENABLED=true
        read -p "Slack webhook URL: " SLACK_WEBHOOK_URL
    fi

    read -p "Enable Discord alerts? (y/n): " enable_discord
    if [ "$enable_discord" = "y" ]; then
        ALERT_DISCORD_ENABLED=true
        read -p "Discord webhook URL: " DISCORD_WEBHOOK_URL
    fi

    read -p "Enable Telegram alerts? (y/n): " enable_telegram
    if [ "$enable_telegram" = "y" ]; then
        ALERT_TELEGRAM_ENABLED=true
        read -p "Telegram bot token: " TELEGRAM_BOT_TOKEN
        read -p "Telegram chat ID: " TELEGRAM_CHAT_ID
    fi

    # Save configuration
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" <<EOF
# Dilithion Alert Handler Configuration
# Generated: $(date)

# Alert channels
ALERT_EMAIL_ENABLED=$ALERT_EMAIL_ENABLED
ALERT_SLACK_ENABLED=$ALERT_SLACK_ENABLED
ALERT_DISCORD_ENABLED=$ALERT_DISCORD_ENABLED
ALERT_TELEGRAM_ENABLED=$ALERT_TELEGRAM_ENABLED
ALERT_LOG_ENABLED=true

# Email configuration
EMAIL_TO="$EMAIL_TO"
EMAIL_FROM="$EMAIL_FROM"

# Slack configuration
SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL"

# Discord configuration
DISCORD_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"

# Telegram configuration
TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
EOF

    chmod 600 "$CONFIG_FILE"

    print_success "Configuration saved to $CONFIG_FILE"
    print_info "Run with --test to verify alert delivery"
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    # Initialize
    init_alert_state
    load_config

    # Parse arguments
    if [ $# -eq 0 ]; then
        echo "Dilithion Alert Handler"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --check                  Run health check and send alerts if issues found"
        echo "  --alert \"message\"        Send custom alert"
        echo "  --test                   Test alert delivery"
        echo "  --setup                  Setup alert configuration"
        echo "  --view-log               View recent alerts"
        echo "  --help                   Show this help message"
        echo ""
        exit 0
    fi

    case "$1" in
        --check)
            run_health_check_and_alert
            ;;
        --alert)
            if [ -z "$2" ]; then
                print_error "Alert message required"
                exit 1
            fi
            send_alert "Custom Alert" "$2" "$SEVERITY_WARNING" "custom_alert"
            ;;
        --test)
            test_alerts
            ;;
        --setup)
            setup_config
            ;;
        --view-log)
            if [ -f "$ALERT_LOG_FILE" ]; then
                tail -n 50 "$ALERT_LOG_FILE"
            else
                print_warning "No alert log found"
            fi
            ;;
        --help)
            echo "Dilithion Alert Handler - Help"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --check                  Run health check and alert on issues"
            echo "  --alert \"message\"        Send custom alert message"
            echo "  --test                   Test alert delivery to all channels"
            echo "  --setup                  Interactive configuration setup"
            echo "  --view-log               View last 50 alerts from log"
            echo "  --help                   Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --check                           # Run health check"
            echo "  $0 --alert \"High CPU usage\"         # Send custom alert"
            echo "  $0 --test                            # Test alerts"
            echo ""
            echo "Cron setup (check every 5 minutes):"
            echo "  */5 * * * * $0 --check"
            echo ""
            echo "Configuration file: $CONFIG_FILE"
            echo ""
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
