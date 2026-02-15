#!/bin/bash
# Agent Passport - Local Mandate Ledger (Expanded)
# Consent-gating for ALL sensitive actions, not just purchases

set -euo pipefail
umask 077

LEDGER_DIR="${AGENT_PASSPORT_LEDGER_DIR:-$HOME/.openclaw/agent-passport}"
LEDGER_FILE="$LEDGER_DIR/mandates.json"
KYA_FILE="$LEDGER_DIR/agents.json"
AUDIT_FILE="$LEDGER_DIR/audit.json"
KILLSWITCH_FILE="$LEDGER_DIR/.killswitch"

SAFE_FIELD_RE='^[A-Za-z0-9._:@/-]+$'
SAFE_PATH_RE='^[A-Za-z0-9._/@*,:+= -]+$'
SAFE_NUMBER_RE='^[0-9]+([.][0-9]+)?$'

json_error() {
    local message="$1"
    printf '{"error": "%s"}\n' "$message"
}

assert_safe_field() {
    local field_name="$1"
    local value="$2"
    if [ -z "$value" ] || ! [[ "$value" =~ $SAFE_FIELD_RE ]]; then
        json_error "Invalid $field_name"
        return 1
    fi
}

assert_safe_path_value() {
    local field_name="$1"
    local value="$2"
    if [ -z "$value" ] || [[ "$value" == *".."* ]] || ! [[ "$value" =~ $SAFE_PATH_RE ]]; then
        json_error "Invalid $field_name"
        return 1
    fi
}

assert_safe_amount() {
    local field_name="$1"
    local value="$2"
    if [ -z "$value" ] || ! [[ "$value" =~ $SAFE_NUMBER_RE ]]; then
        json_error "Invalid $field_name"
        return 1
    fi
}

assert_valid_json() {
    local input="$1"
    if ! printf '%s' "$input" | jq -e . >/dev/null 2>&1; then
        json_error "Invalid JSON payload"
        return 1
    fi
}

safe_write_json_file() {
    local target_file="$1"
    local content="$2"
    local tmp_file
    tmp_file="$(mktemp "$LEDGER_DIR/.tmp.XXXXXX")"
    printf '%s\n' "$content" > "$tmp_file"
    mv -f -- "$tmp_file" "$target_file"
}

safe_write_text_file() {
    local target_file="$1"
    local content="$2"
    local tmp_file
    tmp_file="$(mktemp "$LEDGER_DIR/.tmp.XXXXXX")"
    printf '%s\n' "$content" > "$tmp_file"
    mv -f -- "$tmp_file" "$target_file"
}

validate_ledger_dir() {
    if [ -z "$LEDGER_DIR" ] || [[ "$LEDGER_DIR" == *".."* ]] || [[ "$LEDGER_DIR" == *$'\n'* ]]; then
        echo "Error: Invalid ledger directory path" >&2
        return 1
    fi
}

# Action categories
# - financial: purchases, transfers, subscriptions
# - communication: emails, messages, posts
# - data: file deletion, document edits, database writes
# - system: shell commands, package installs, config changes
# - external_api: third-party API calls with side effects
# - identity: public actions "as" the user

init_ledger() {
    validate_ledger_dir
    mkdir -p -- "$LEDGER_DIR"
    if [ ! -f "$LEDGER_FILE" ]; then
        safe_write_json_file "$LEDGER_FILE" '{"mandates":[],"version":"2.1.0"}'
    fi
    if [ ! -f "$KYA_FILE" ]; then
        safe_write_json_file "$KYA_FILE" '{"agents":[],"version":"1.0"}'
    fi
    if [ ! -f "$AUDIT_FILE" ]; then
        safe_write_json_file "$AUDIT_FILE" '{"entries":[],"version":"1.0"}'
    fi
}

kill_switch_engaged() {
    [ -f "$KILLSWITCH_FILE" ]
}

generate_id() {
    local prefix="${1:-mandate}"
    echo "${prefix}_$(date +%s)_$(head -c 4 /dev/urandom | xxd -p)"
}

# Audit logging
audit_log() {
    init_ledger
    local action="${1:-}"
    local mandate_id="${2:-}"
    local details="${3:-}"
    local result="${4:-}"
    local now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local entry_id=$(generate_id "audit")
    
    local entry=$(jq -n \
        --arg id "$entry_id" \
        --arg action "$action" \
        --arg mandate "$mandate_id" \
        --arg details "$details" \
        --arg result "$result" \
        --arg ts "$now" \
        '{entry_id: $id, action: $action, mandate_id: $mandate, details: $details, result: $result, timestamp: $ts}')
    
    local updated
    updated="$(jq --argjson e "$entry" '.entries += [$e]' "$AUDIT_FILE")"
    safe_write_json_file "$AUDIT_FILE" "$updated"
}

create_mandate() {
    init_ledger
    local id
    id="$(generate_id)"
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    local payload="${1:-}"

    if ! assert_valid_json "$payload"; then
        return 1
    fi
    
    # Validate action_type
    local action_type
    action_type="$(printf '%s' "$payload" | jq -r '.action_type // "financial"')"
    case "$action_type" in
        financial|communication|data|system|external_api|identity)
            ;;
        *)
            echo '{"error": "Invalid action_type. Must be: financial, communication, data, system, external_api, or identity"}'
            return 1
            ;;
    esac
    
    # Validate required fields
    local agent_id
    agent_id="$(printf '%s' "$payload" | jq -r '.agent_id // empty')"
    if [ -z "$agent_id" ]; then
        echo '{"error": "Missing required field: agent_id"}'
        return 1
    fi
    if ! assert_safe_field "agent_id" "$agent_id"; then
        return 1
    fi
    
    local ttl
    ttl="$(printf '%s' "$payload" | jq -r '.ttl // empty')"
    if [ -z "$ttl" ]; then
        echo '{"error": "Missing required field: ttl"}'
        return 1
    fi
    
    local has_scope
    has_scope="$(printf '%s' "$payload" | jq 'has("scope")')"
    if [ "$has_scope" != "true" ]; then
        echo '{"error": "Missing required field: scope"}'
        return 1
    fi
    
    # Reject expired TTL
    if [[ "$ttl" < "$now" ]]; then
        echo "{\"error\": \"TTL is already expired\", \"ttl\": \"$ttl\"}"
        return 1
    fi
    
    # Add metadata and defaults
    local mandate
    mandate="$(printf '%s' "$payload" | jq \
        --arg id "$id" \
        --arg created "$now" \
        --arg status "active" \
        --arg action_type "$action_type" \
        '. + {
            mandate_id: $id, 
            created_at: $created, 
            status: $status,
            action_type: $action_type,
            usage: (.usage // {count: 0, total_amount: 0})
        }')"
    
    # Append to ledger
    local updated
    updated="$(jq --argjson m "$mandate" '.mandates += [$m]' "$LEDGER_FILE")"
    safe_write_json_file "$LEDGER_FILE" "$updated"
    
    audit_log "create" "$id" "$action_type mandate created" "success"
    echo "$mandate"
}

get_mandate() {
    init_ledger
    local id="${1:-}"
    if [ -z "$id" ]; then
        echo '{"error": "Usage: get <mandate_id>"}'
        return 1
    fi
    local result
    result="$(jq --arg id "$id" '.mandates[] | select(.mandate_id == $id)' "$LEDGER_FILE")"
    if [ -z "$result" ]; then
        echo '{"error": "Mandate not found: '"$id"'"}'
        return 1
    fi
    echo "$result"
}

list_mandates() {
    init_ledger
    local filter="${1:-all}"
    
    # Can filter by status (active/revoked/expired) or action_type
    case "$filter" in
        all)
            jq '.mandates' "$LEDGER_FILE"
            ;;
        active|revoked|expired)
            jq --arg s "$filter" '.mandates | map(select(.status == $s))' "$LEDGER_FILE"
            ;;
        financial|communication|data|system|external_api|identity)
            jq --arg t "$filter" '.mandates | map(select(.action_type == $t))' "$LEDGER_FILE"
            ;;
        *)
            jq --arg s "$filter" '.mandates | map(select(.status == $s or .action_type == $s))' "$LEDGER_FILE"
            ;;
    esac
}

revoke_mandate() {
    init_ledger
    local id="${1:-}"
    local reason="${2:-revoked by user}"
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if ! assert_safe_field "mandate_id" "$id"; then
        return 1
    fi
    
    local updated
    updated="$(jq --arg id "$id" --arg reason "$reason" --arg revoked "$now" \
        '.mandates = [.mandates[] | if .mandate_id == $id then . + {status: "revoked", revoked_at: $revoked, revoke_reason: $reason} else . end]' \
        "$LEDGER_FILE")"
    safe_write_json_file "$LEDGER_FILE" "$updated"
    
    audit_log "revoke" "$id" "reason: $reason" "success"
    get_mandate "$id"
}

# Universal action check - works for all action types
check_action() {
    init_ledger
    local agent_id="${1:-}"
    local action_type="${2:-}"
    local target="${3:-}"      # merchant_id for financial, recipient for comms, path for data, etc.
    local amount="${4:-}"      # amount for financial, count for rate-limited actions
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if ! assert_safe_field "agent_id" "$agent_id"; then
        return 1
    fi
    if ! assert_safe_field "action_type" "$action_type"; then
        return 1
    fi
    if [ "$action_type" = "data" ] && ! assert_safe_path_value "target" "$target"; then
        return 1
    fi

    if kill_switch_engaged; then
        echo '{"authorized": false, "reason": "Kill switch engaged", "kill_switch": true}'
        return 0
    fi
    
    # Default amount to 1 for non-financial
    amount="${amount:-1}"
    if ! assert_safe_amount "amount" "$amount"; then
        return 1
    fi
    
    # Check if ledger is completely empty
    local total_mandates
    total_mandates="$(jq '.mandates | length' "$LEDGER_FILE")"
    if [ "$total_mandates" -eq 0 ]; then
        echo '{"authorized": false, "reason": "No mandates exist yet. Create one with: mandate-ledger.sh create-from-template dev-tools <agent_id>", "hint": "templates"}'
        return 0
    fi

    # Find valid mandate for this action type
    local mandate
    mandate="$(jq -c \
        --arg agent "$agent_id" \
        --arg type "$action_type" \
        --arg target "$target" \
        --argjson amt "$amount" \
        --arg now "$now" \
        '[.mandates[] | select(
            .agent_id == $agent and 
            .action_type == $type and
            .status == "active" and 
            .ttl > $now and
            (
                # Check target allowlist if present
                (.scope.allowlist == null) or 
                (.scope.allowlist | length == 0) or
                (.scope.allowlist | any(
                    . as $pattern |
                    if ($pattern == "all" or $pattern == "*") then
                        true
                    elif (($pattern | startswith("*")) and ($pattern | endswith("*"))) then
                        # Double wildcard: contains match
                        ($target | contains($pattern[1:-1]))
                    elif ($pattern | startswith("*@")) then
                        # Wildcard domain match: *@domain.com matches user@domain.com
                        ($target | endswith($pattern[1:]))
                    elif ($pattern | startswith("*")) then
                        # Wildcard prefix: *.env matches foo.env
                        ($target | endswith($pattern[1:]))
                    elif ($pattern | endswith("*")) then
                        # Wildcard suffix match: "git *" matches "git status"
                        ($target | startswith($pattern[:-1]))
                    else
                        # Exact match
                        ($pattern == $target)
                    end
                ))
            ) and
            (
                # Check deny list - reject if target matches any deny pattern
                (.scope.deny == null) or
                (.scope.deny | length == 0) or
                (.scope.deny | all(
                    . as $pattern |
                    if (($pattern | startswith("*")) and ($pattern | endswith("*"))) then
                        # Double wildcard: */.git/* matches anything containing /.git/
                        ($target | contains($pattern[1:-1])) | not
                    elif ($pattern | startswith("*")) then
                        # Wildcard prefix: *.env, *.key
                        ($target | endswith($pattern[1:])) | not
                    elif ($pattern | endswith("*")) then
                        # Wildcard suffix: sudo *, rm -rf /*
                        ($target | startswith($pattern[:-1])) | not
                    else
                        ($pattern != $target)
                    end
                ))
            ) and
            (
                # Check cap (amount_cap for financial, rate_limit for others)
                (.amount_cap == null) or
                ((.usage.total_amount // 0) + $amt <= .amount_cap)
            ) and
            (
                # Check rate limit if present
                # TODO: Rate limit windows not yet implemented - count is cumulative per mandate lifetime
                (.scope.rate_limit == null) or
                ((.usage.count // 0) < (.scope.rate_limit | split("/")[0] | tonumber))
            )
        )] | first // null' "$LEDGER_FILE")"
    
    if [ "$mandate" != "null" ] && [ -n "$mandate" ]; then
        local mandate_id
        mandate_id="$(printf '%s' "$mandate" | jq -r '.mandate_id')"
        local remaining=""
        
        # Calculate remaining based on action type
        if [ "$action_type" = "financial" ]; then
            local cap
            cap="$(printf '%s' "$mandate" | jq -r '.amount_cap // 0')"
            local used
            used="$(printf '%s' "$mandate" | jq -r '.usage.total_amount // 0')"
            if assert_safe_amount "amount_cap" "$cap" && assert_safe_amount "used" "$used"; then
                remaining="$(awk -v c="$cap" -v u="$used" 'BEGIN { printf "%.10g", c - u }')"
            fi
        fi
        
        echo '{"authorized": true, "mandate_id": "'"$mandate_id"'", "action_type": "'"$action_type"'", "target": "'"$target"'"'"$([ -n "$remaining" ] && echo ', "remaining": '$remaining)"'}'
    else
        echo '{"authorized": false, "action_type": "'"$action_type"'", "target": "'"$target"'", "reason": "No valid mandate found"}'
    fi
}

# Legacy check for backwards compatibility
check_mandate() {
    check_action "${1:-}" "financial" "${2:-}" "${3:-}"
}

# Log action against a mandate (universal)
log_action() {
    init_ledger
    local id="${1:-}"
    local amount="${2:-1}"
    local description="${3:-action performed}"
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if ! assert_safe_field "mandate_id" "$id"; then
        return 1
    fi
    if ! assert_safe_amount "amount" "$amount"; then
        return 1
    fi
    
    # Get current mandate
    local mandate
    mandate="$(jq -c --arg id "$id" '.mandates[] | select(.mandate_id == $id)' "$LEDGER_FILE")"
    
    if [ -z "$mandate" ] || [ "$mandate" = "null" ]; then
        echo '{"error": "Mandate not found"}'
        return 1
    fi
    
    local status
    status="$(printf '%s' "$mandate" | jq -r '.status')"
    local ttl
    ttl="$(printf '%s' "$mandate" | jq -r '.ttl')"
    local action_type
    action_type="$(printf '%s' "$mandate" | jq -r '.action_type')"
    
    if [ "$status" != "active" ]; then
        echo '{"error": "Mandate not active", "status": "'"$status"'"}'
        return 1
    fi
    
    if [[ "$ttl" < "$now" ]]; then
        echo '{"error": "Mandate expired", "ttl": "'"$ttl"'"}'
        return 1
    fi
    
    # Check caps based on action type
    if [ "$action_type" = "financial" ]; then
        local cap
        cap="$(printf '%s' "$mandate" | jq -r '.amount_cap // 0')"
        local used
        used="$(printf '%s' "$mandate" | jq -r '.usage.total_amount // 0')"
        local new_used
        new_used="$(awk -v u="$used" -v a="$amount" 'BEGIN { printf "%.10g", u + a }')"
        
        if awk -v n="$new_used" -v c="$cap" 'BEGIN { exit !(n > c) }'; then
            echo '{"error": "Exceeds cap", "cap": '$cap', "used": '$used', "requested": '$amount'}'
            return 1
        fi
    fi
    
    # Check rate limit
    local rate_limit
    rate_limit="$(printf '%s' "$mandate" | jq -r '.scope.rate_limit // empty')"
    if [ -n "$rate_limit" ]; then
        if ! [[ "$rate_limit" =~ ^[0-9]+/(day|hour|minute|week|month|year)$ ]]; then
            echo '{"error": "Invalid rate_limit format", "rate_limit": "'"$rate_limit"'"}'
            return 1
        fi
        local limit_count
        limit_count="$(printf '%s' "$rate_limit" | cut -d'/' -f1)"
        local current_count
        current_count="$(printf '%s' "$mandate" | jq -r '.usage.count // 0')"
        if (( current_count >= limit_count )); then
            echo '{"error": "Rate limit exceeded", "limit": "'"$rate_limit"'", "current": '$current_count'}'
            return 1
        fi
    fi
    
    # Update usage
    local updated
    updated="$(jq --arg id "$id" --argjson amt "$amount" \
        '.mandates = [.mandates[] | if .mandate_id == $id then 
            .usage.count = ((.usage.count // 0) + 1) |
            .usage.total_amount = ((.usage.total_amount // 0) + $amt)
        else . end]' "$LEDGER_FILE")"
    safe_write_json_file "$LEDGER_FILE" "$updated"
    
    # Get updated stats
    local new_count
    new_count="$(printf '%s' "$updated" | jq --arg id "$id" '.mandates[] | select(.mandate_id == $id) | .usage.count')"
    local new_total
    new_total="$(printf '%s' "$updated" | jq --arg id "$id" '.mandates[] | select(.mandate_id == $id) | .usage.total_amount')"
    
    audit_log "action" "$id" "$description" "success"
    
    echo '{"success": true, "mandate_id": "'"$id"'", "action_type": "'"$action_type"'", "usage": {"count": '$new_count', "total_amount": '$new_total'}}'
}

# Legacy spend for backwards compatibility
spend() {
    log_action "${1:-}" "${2:-}" "financial transaction"
}

export_ledger() {
    init_ledger
    local mandates agents audit
    mandates="$(jq '.mandates' "$LEDGER_FILE")"
    agents="$(jq '.agents' "$KYA_FILE" 2>/dev/null || echo '[]')"
    audit="$(jq '.entries' "$AUDIT_FILE" 2>/dev/null || echo '[]')"
    jq -n --argjson m "$mandates" --argjson a "$agents" --argjson au "$audit" \
        '{"mandates": $m, "agents": $a, "audit": $au, "version": "2.1.0", "exported_at": (now | todate)}'
}

# Audit commands
audit_list() {
    init_ledger
    local limit="${1:-20}"
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
        echo '{"error":"Invalid limit"}'
        return 1
    fi
    jq --argjson n "$limit" '.entries | sort_by(.timestamp) | reverse | .[:$n]' "$AUDIT_FILE"
}

audit_for_mandate() {
    init_ledger
    local mandate_id="${1:-}"
    jq --arg id "$mandate_id" '.entries | map(select(.mandate_id == $id))' "$AUDIT_FILE"
}

audit_summary() {
    init_ledger
    local since="${1:-}"
    
    if [ -n "$since" ]; then
        jq --arg since "$since" '
            .entries | map(select(.timestamp >= $since)) | 
            group_by(.action) | 
            map({action: .[0].action, count: length})
        ' "$AUDIT_FILE"
    else
        jq '
            .entries | 
            group_by(.action) | 
            map({action: .[0].action, count: length})
        ' "$AUDIT_FILE"
    fi
}

# KYA (Know Your Agent) functions
kya_register() {
    init_ledger
    local agent_id="${1:-}"
    local principal="${2:-}"
    local scope="${3:-}"
    local provider="${4:-self-declared}"
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if ! assert_safe_field "agent_id" "$agent_id"; then
        return 1
    fi
    
    # Check if agent already exists
    local existing
    existing="$(jq -c --arg id "$agent_id" '.agents[] | select(.agent_id == $id)' "$KYA_FILE")"
    
    if [ -n "$existing" ]; then
        # Update existing
        local updated
        updated="$(jq --arg id "$agent_id" --arg principal "$principal" --arg scope "$scope" --arg provider "$provider" --arg now "$now" \
            '.agents = [.agents[] | if .agent_id == $id then . + {
                verified_principal: $principal,
                authorization_scope: $scope,
                provider: $provider,
                verified_at: $now,
                status: "verified"
            } else . end]' "$KYA_FILE")"
        safe_write_json_file "$KYA_FILE" "$updated"
    else
        # Create new
        local agent
        agent="$(jq -n --arg id "$agent_id" --arg principal "$principal" --arg scope "$scope" --arg provider "$provider" --arg now "$now" '{
            agent_id: $id,
            verified_principal: $principal,
            authorization_scope: $scope,
            provider: $provider,
            verified_at: $now,
            status: "verified",
            created_at: $now
        }')"
        local updated
        updated="$(jq --argjson agent "$agent" '.agents += [$agent]' "$KYA_FILE")"
        safe_write_json_file "$KYA_FILE" "$updated"
    fi
    
    audit_log "kya_register" "$agent_id" "principal: $principal" "success"
    kya_get "$agent_id"
}

kya_get() {
    init_ledger
    local agent_id="${1:-}"
    jq -c --arg id "$agent_id" '.agents[] | select(.agent_id == $id)' "$KYA_FILE"
}

kya_list() {
    init_ledger
    jq '.agents' "$KYA_FILE"
}

kya_revoke() {
    init_ledger
    local agent_id="${1:-}"
    local reason="${2:-revoked by user}"
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if ! assert_safe_field "agent_id" "$agent_id"; then
        return 1
    fi
    
    local updated
    updated="$(jq --arg id "$agent_id" --arg reason "$reason" --arg now "$now" \
        '.agents = [.agents[] | if .agent_id == $id then . + {status: "revoked", revoked_at: $now, revoke_reason: $reason} else . end]' \
        "$KYA_FILE")"
    safe_write_json_file "$KYA_FILE" "$updated"
    
    audit_log "kya_revoke" "$agent_id" "reason: $reason" "success"
    kya_get "$agent_id"
}

# Create mandate with auto-KYA attachment
create_mandate_with_kya() {
    init_ledger
    local payload="${1:-}"
    if ! assert_valid_json "$payload"; then
        return 1
    fi
    local agent_id
    agent_id="$(printf '%s' "$payload" | jq -r '.agent_id')"
    if ! assert_safe_field "agent_id" "$agent_id"; then
        return 1
    fi
    
    # Look up KYA for this agent
    local kya
    kya="$(jq -c --arg id "$agent_id" '.agents[] | select(.agent_id == $id and .status == "verified")' "$KYA_FILE")"
    
    if [ -n "$kya" ]; then
        # Attach KYA to scope
        payload="$(printf '%s' "$payload" | jq --argjson kya "$kya" '.scope.kya = $kya')"
    else
        # Mark as unknown
        payload="$(printf '%s' "$payload" | jq '.scope.kya = {status: "unknown"}')"
    fi
    
    create_mandate "$payload"
}

summary() {
    init_ledger
    local now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    echo "Agent Passport Local Ledger v2.1.0"
    echo "================================="
    echo ""
    
    # Overall stats
    local total=$(jq '.mandates | length' "$LEDGER_FILE")
    local active=$(jq --arg now "$now" '[.mandates[] | select(.status == "active" and .ttl > $now)] | length' "$LEDGER_FILE")
    local revoked=$(jq '[.mandates[] | select(.status == "revoked")] | length' "$LEDGER_FILE")
    local expired=$(jq --arg now "$now" '[.mandates[] | select(.status == "active" and .ttl <= $now)] | length' "$LEDGER_FILE")
    
    echo "Mandates: $total total ($active active, $expired expired, $revoked revoked)"
    echo ""
    
    # By action type
    echo "By Category:"
    for type in financial communication data system external_api identity; do
        local count=$(jq --arg t "$type" '[.mandates[] | select(.action_type == $t)] | length' "$LEDGER_FILE")
        if [ "$count" -gt 0 ]; then
            local type_active=$(jq --arg t "$type" --arg now "$now" '[.mandates[] | select(.action_type == $t and .status == "active" and .ttl > $now)] | length' "$LEDGER_FILE")
            printf "  %-14s %d (%d active)\n" "$type:" "$count" "$type_active"
        fi
    done
    echo ""
    
    # Financial totals
    local total_cap=$(jq '[.mandates[] | select(.action_type == "financial") | .amount_cap // 0] | add // 0' "$LEDGER_FILE")
    local total_used=$(jq '[.mandates[] | select(.action_type == "financial") | .usage.total_amount // 0] | add // 0' "$LEDGER_FILE")
    echo "Financial: \$$total_used used of \$$total_cap authorized"
    
    # Action counts
    local total_actions=$(jq '[.mandates[].usage.count // 0] | add // 0' "$LEDGER_FILE")
    echo "Total actions logged: $total_actions"
    
    # Audit entries
    local audit_count=$(jq '.entries | length' "$AUDIT_FILE")
    echo "Audit entries: $audit_count"
}

kill_ledger() {
    init_ledger
    if [ -z "${*}" ]; then
        echo '{"error": "Usage: kill <reason> — reason is required"}'
        return 1
    fi
    local reason="${*}"
    local kill_payload
    kill_payload="$(printf 'reason=%s\ntimestamp=%s\n' "$reason" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")")"
    safe_write_text_file "$KILLSWITCH_FILE" "$kill_payload"

    audit_log "kill" "system" "reason: $reason" "success"
    echo "AGENT PASSPORT: KILL SWITCH ENGAGED. Execution frozen."
    echo "Reason: $reason"
}

unlock_ledger() {
    init_ledger

    if [ -f "$KILLSWITCH_FILE" ]; then
        rm -f -- "$KILLSWITCH_FILE"
        audit_log "unlock" "system" "kill switch removed" "success"
        echo "AGENT PASSPORT: KILL SWITCH DISENGAGED. Operations restored."
    else
        audit_log "unlock" "system" "unlock requested with no active kill switch" "success"
        echo "AGENT PASSPORT: Kill switch was not engaged."
    fi
}

# Parse TTL duration string (7d, 24h, 30d) to ISO timestamp
parse_ttl_duration() {
    local duration="${1:-}"
    if ! [[ "$duration" =~ ^[0-9]+[dhm]$ ]]; then
        echo "Invalid duration: $duration (use e.g. 7d, 24h, 30m)" >&2
        return 1
    fi
    local num="${duration%[dhm]}"
    local unit="${duration: -1}"
    
    case "$unit" in
        d) local seconds=$((num * 86400)) ;;
        h) local seconds=$((num * 3600)) ;;
        m) local seconds=$((num * 60)) ;;
        *) echo "Invalid duration: $duration (use e.g. 7d, 24h, 30m)" >&2; return 1 ;;
    esac
    
    date -u -d "+${seconds} seconds" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
    date -u -v+${seconds}S +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null
}

# Template definitions
get_template() {
    local template="${1:-}"
    local agent_id="${2:-}"
    shift 2
    
    if [ -z "$agent_id" ]; then
        echo "Error: agent_id required. Usage: create-from-template <template> <agent_id> [args...]" >&2
        return 1
    fi
    if ! assert_safe_field "template" "$template" >/dev/null; then
        echo "Error: invalid template value" >&2
        return 1
    fi
    if ! assert_safe_field "agent_id" "$agent_id" >/dev/null; then
        echo "Error: invalid agent_id" >&2
        return 1
    fi
    
    local ttl_30d=$(parse_ttl_duration "30d")
    local ttl_24h=$(parse_ttl_duration "24h")
    local ttl_7d=$(parse_ttl_duration "7d")
    local ttl_1d=$(parse_ttl_duration "1d")
    
    case "$template" in
        dev-tools)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_30d" '{
                action_type: "system",
                agent_id: $agent,
                scope: {
                    allowlist: ["git *", "npm *", "yarn *", "cargo *", "make *", "docker *", "python *", "pip *", "bun *"],
                    deny: ["sudo *", "rm -rf /*", "chmod 777 *"]
                },
                ttl: $ttl
            }'
            ;;
        email-team)
            local domain="${1:-}"
            if [ -z "$domain" ]; then
                echo "Error: domain required. Usage: create-from-template email-team <agent_id> <domain>" >&2
                return 1
            fi
            if [[ "$domain" == *".."* ]] || [[ "$domain" == *"/"* ]] || [[ "$domain" == *"\\"* ]] || ! [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
                echo "Error: invalid domain" >&2
                return 1
            fi
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_30d" --arg pattern "*@${domain}" '{
                action_type: "communication",
                agent_id: $agent,
                scope: {
                    allowlist: [$pattern],
                    rate_limit: "50/day"
                },
                ttl: $ttl
            }'
            ;;
        file-ops)
            local basepath="${1:-}"
            if [ -z "$basepath" ]; then
                echo "Error: base path required. Usage: create-from-template file-ops <agent_id> <path>" >&2
                return 1
            fi
            if ! assert_safe_path_value "basepath" "$basepath" >/dev/null; then
                echo "Error: invalid base path" >&2
                return 1
            fi
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_30d" --arg pattern "${basepath}/*" '{
                action_type: "data",
                agent_id: $agent,
                scope: {
                    allowlist: [$pattern],
                    deny: ["*.env", "*.key", "*.pem", "*/.git/*"]
                },
                ttl: $ttl
            }'
            ;;
        web-research)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_30d" '{
                action_type: "external_api",
                agent_id: $agent,
                scope: {
                    allowlist: ["api.github.com", "api.openai.com", "api.anthropic.com"],
                    rate_limit: "200/hour"
                },
                ttl: $ttl
            }'
            ;;
        safe-browsing)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_24h" '{
                action_type: "external_api",
                agent_id: $agent,
                scope: {
                    allowlist: ["google.com", "wikipedia.org", "github.com", "stackoverflow.com"],
                    rate_limit: "30/hour"
                },
                ttl: $ttl
            }'
            ;;
        coding)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_7d" '{
                action_type: "system",
                agent_id: $agent,
                scope: {
                    allowlist: [
                        "git", "git *",
                        "npm", "npm *",
                        "node", "node *",
                        "python", "python *",
                        "pip", "pip *",
                        "cargo", "cargo *",
                        "make", "make *",
                        "docker", "docker *"
                    ],
                    rate_limit: "100/hour"
                },
                ttl: $ttl
            }'
            ;;
        email-assistant)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_24h" '{
                action_type: "communication",
                agent_id: $agent,
                scope: {
                    allowlist: ["all"],
                    rate_limit: "20/hour"
                },
                amount_cap: 0,
                ttl: $ttl
            }'
            ;;
        read-only)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_24h" '{
                action_type: "data",
                agent_id: $agent,
                scope: {
                    allowlist: ["read", "list", "cat", "ls"],
                    rate_limit: "50/hour"
                },
                ttl: $ttl
            }'
            ;;
        full-auto)
            jq -n --arg agent "$agent_id" --arg ttl "$ttl_1d" '{
                action_type: "system",
                agent_id: $agent,
                scope: {
                    allowlist: ["all"],
                    rate_limit: "200/hour"
                },
                ttl: $ttl
            }'
            ;;
        *)
            echo "Error: Unknown template '$template'. Available: dev-tools, email-team, file-ops, web-research, safe-browsing, coding, email-assistant, read-only, full-auto" >&2
            return 1
            ;;
    esac
}

get_default_agent() {
    init_ledger
    local count=$(jq '.agents | map(select(.status == "verified")) | length' "$KYA_FILE")
    if [ "$count" -eq 1 ]; then
        jq -r '.agents[] | select(.status == "verified") | .agent_id' "$KYA_FILE"
    else
        echo ""
    fi
}

create_from_template() {
    local template="${1:-}"
    shift
    local agent_id="${1:-}"
    
    # Auto-detect agent_id if not provided
    if [ -z "$agent_id" ]; then
        agent_id=$(get_default_agent)
        if [ -z "$agent_id" ]; then
            echo '{"error": "No agent_id provided. Register an agent first: mandate-ledger.sh init <agent_id> <principal>"}'
            return 1
        fi
    fi
    
    local payload
    if ! payload="$(get_template "$template" "$agent_id" "${@:2}")"; then
        echo "$payload"
        return 1
    fi
    
    # Check if agent has KYA entry, use create_mandate_with_kya if so
    local kya
    kya="$(jq -c --arg id "$agent_id" '.agents[] | select(.agent_id == $id and .status == "verified")' "$KYA_FILE" 2>/dev/null || true)"
    if [ -n "$kya" ]; then
        create_mandate_with_kya "$payload"
    else
        create_mandate "$payload"
    fi
}

create_quick() {
    local action_type="${1:-}"
    local agent_id="${2:-}"
    local allowlist_csv="${3:-}"
    local ttl_duration="${4:-}"
    local amount_cap="${5:-}"
    
    # Auto-detect agent_id if empty
    if [ -z "$agent_id" ]; then
        agent_id=$(get_default_agent)
        if [ -z "$agent_id" ]; then
            echo '{"error": "No agent_id provided. Register an agent first: mandate-ledger.sh init <agent_id> <principal>"}'
            return 1
        fi
    fi
    
    if [ -z "$action_type" ] || [ -z "$allowlist_csv" ] || [ -z "$ttl_duration" ]; then
        echo '{"error": "Usage: create-quick <action_type> <agent_id> <allowlist_csv> <ttl_duration> [amount_cap]"}'
        return 1
    fi
    if ! assert_safe_field "action_type" "$action_type"; then
        return 1
    fi
    if ! assert_safe_field "agent_id" "$agent_id"; then
        return 1
    fi
    if [[ "$allowlist_csv" == *'`'* ]] || [[ "$allowlist_csv" == *'$('* ]] || [[ "$allowlist_csv" == *';'* ]] || [[ "$allowlist_csv" == *'|'* ]]; then
        json_error "Invalid allowlist_csv"
        return 1
    fi
    if [ -n "${amount_cap:-}" ] && ! assert_safe_amount "amount_cap" "$amount_cap"; then
        return 1
    fi
    
    local ttl
    if ! ttl="$(parse_ttl_duration "$ttl_duration")"; then
        echo '{"error": "Invalid TTL duration: '"$ttl_duration"'. Use e.g. 7d, 24h, 30m"}'
        return 1
    fi
    if [ -z "$ttl" ]; then
        echo '{"error": "Invalid TTL duration: '"$ttl_duration"'. Use e.g. 7d, 24h, 30m"}'
        return 1
    fi
    
    # Convert CSV to JSON array
    local allowlist
    allowlist="$(printf '%s' "$allowlist_csv" | jq -R 'split(",")')"
    
    local payload
    if [ -n "$amount_cap" ]; then
        payload=$(jq -n \
            --arg type "$action_type" \
            --arg agent "$agent_id" \
            --argjson allow "$allowlist" \
            --arg ttl "$ttl" \
            --argjson cap "$amount_cap" \
            '{action_type: $type, agent_id: $agent, scope: {allowlist: $allow}, ttl: $ttl, amount_cap: $cap}')
    else
        payload=$(jq -n \
            --arg type "$action_type" \
            --arg agent "$agent_id" \
            --argjson allow "$allowlist" \
            --arg ttl "$ttl" \
            '{action_type: $type, agent_id: $agent, scope: {allowlist: $allow}, ttl: $ttl}')
    fi
    
    # Check if agent has KYA entry
    init_ledger
    local kya
    kya="$(jq -c --arg id "$agent_id" '.agents[] | select(.agent_id == $id and .status == "verified")' "$KYA_FILE" 2>/dev/null || true)"
    if [ -n "$kya" ]; then
        create_mandate_with_kya "$payload"
    else
        create_mandate "$payload"
    fi
}

init_passport() {
    local agent_id="${2:-}"
    local principal="${3:-}"
    local scope="${4:-}"
    local provider="${5:-}"
    
    local mandate_count=0
    if [ -f "$LEDGER_FILE" ]; then
        mandate_count="$(jq '.mandates | length' "$LEDGER_FILE" 2>/dev/null || echo 0)"
        if [ "$mandate_count" -gt 0 ] || [ -f "$AUDIT_FILE" ]; then
            # Already initialized
            init_ledger
            
            # If KYA args provided, register/update
            if [ -n "$agent_id" ] && [ -n "$principal" ]; then
                kya_register "$agent_id" "$principal" "$scope" "$provider" > /dev/null
                echo "Already initialized at $LEDGER_DIR/ ($mandate_count mandates)"
                echo "🪪 Registered agent: $agent_id (principal: $principal)"
                return 0
            fi
            
            # Check for existing registered agent
            local registered
            registered="$(jq -r '.agents[] | select(.status == "verified") | "\(.agent_id) (principal: \(.verified_principal))"' "$KYA_FILE" 2>/dev/null | head -1 || true)"
            if [ -n "$registered" ]; then
                echo "Already initialized at $LEDGER_DIR/ ($mandate_count mandates)"
                echo "🪪 Registered agent: $registered"
            else
                echo "Already initialized at $LEDGER_DIR/ ($mandate_count mandates)"
            fi
            return 0
        fi
    fi
    
    init_ledger
    
    # If KYA args provided, register agent
    if [ -n "$agent_id" ] && [ -n "$principal" ]; then
        kya_register "$agent_id" "$principal" "$scope" "$provider" > /dev/null
        echo "✅ Agent Passport initialized at $LEDGER_DIR/"
        echo "🪪 Agent registered: $agent_id (principal: $principal)"
    else
        echo "✅ Agent Passport initialized at $LEDGER_DIR/"
        echo ""
        echo "⚠️  No agent registered yet. Register your agent for full KYA tracking:"
        echo "  ./mandate-ledger.sh init agent:my-assistant \"Your Name\" \"assistant scope\" \"openclaw\""
    fi
    
    echo ""
    echo "Quick start:"
    echo "  # Use a template:"
    echo "  ./mandate-ledger.sh create-from-template dev-tools"
    echo ""
    echo "  # Or create manually:"
    echo "  ./mandate-ledger.sh create-quick system \"\" \"git *,npm *\" 7d"
    echo ""
    echo "  # Check if an action is allowed:"
    echo "  ./mandate-ledger.sh check-action agent:seb system \"git pull\""
    echo ""
    echo "Available templates: dev-tools, email-team, file-ops, web-research, safe-browsing, coding, email-assistant, read-only, full-auto"
    echo "Run: ./mandate-ledger.sh templates"
}

list_templates() {
    echo "Available templates:"
    echo ""
    echo "  dev-tools                     System commands (git, npm, docker, cargo, etc.)"
    echo "    Usage: create-from-template dev-tools <agent_id>"
    echo "    Deny: sudo, rm -rf /*, chmod 777  |  TTL: 30 days"
    echo ""
    echo "  email-team                    Internal email communication"
    echo "    Usage: create-from-template email-team <agent_id> <domain>"
    echo "    Rate: 50/day  |  TTL: 30 days"
    echo ""
    echo "  file-ops                      File management within a directory"
    echo "    Usage: create-from-template file-ops <agent_id> <path>"
    echo "    Deny: *.env, *.key, *.pem, .git  |  TTL: 30 days"
    echo ""
    echo "  web-research                  API access (GitHub, OpenAI, Anthropic)"
    echo "    Usage: create-from-template web-research <agent_id>"
    echo "    Rate: 200/hour  |  TTL: 30 days"
    echo ""
    echo "  safe-browsing                 Safer web/API browsing to trusted sites"
    echo "    Usage: create-from-template safe-browsing <agent_id>"
    echo "    Allow: google.com, wikipedia.org, github.com, stackoverflow.com"
    echo "    Rate: 30/hour  |  TTL: 24 hours"
    echo ""
    echo "  coding                        High-throughput coding command access"
    echo "    Usage: create-from-template coding <agent_id>"
    echo "    Allow: git, npm, node, python, pip, cargo, make, docker"
    echo "    Rate: 100/hour  |  TTL: 7 days"
    echo ""
    echo "  email-assistant               Broad email assistant communication"
    echo "    Usage: create-from-template email-assistant <agent_id>"
    echo "    Allow: all  |  Amount cap: 0"
    echo "    Rate: 20/hour  |  TTL: 24 hours"
    echo ""
    echo "  read-only                     Read/list oriented data operations"
    echo "    Usage: create-from-template read-only <agent_id>"
    echo "    Allow: read, list, cat, ls"
    echo "    Rate: 50/hour  |  TTL: 24 hours"
    echo ""
    echo "  full-auto                     Maximum automation scope"
    echo "    Usage: create-from-template full-auto <agent_id>"
    echo "    Allow: all"
    echo "    Rate: 200/hour  |  TTL: 1 day"
}

# Command dispatcher
if kill_switch_engaged && [ "${1:-}" != "unlock" ]; then
    echo "AGENT PASSPORT: KILL SWITCH ENGAGED. All operations denied. Run: mandate-ledger.sh unlock" >&2
    exit 1
fi

case "${1:-}" in
    init)
        init_passport "$@"
        ;;
    templates)
        list_templates
        ;;
    create-from-template)
        create_from_template "${2:-}" "${3:-}" "${4:-}" "${5:-}"
        ;;
    create-quick)
        create_quick "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}"
        ;;
    create)
        create_mandate "${2:-}"
        ;;
    create-with-kya)
        create_mandate_with_kya "${2:-}"
        ;;
    get)
        get_mandate "${2:-}"
        ;;
    list)
        list_mandates "${2:-}"
        ;;
    revoke)
        revoke_mandate "${2:-}" "${3:-}"
        ;;
    check)
        # Legacy: check <agent> <merchant> <amount>
        # New:    check <agent> <action_type> <target> [amount]
        if [ "$#" -eq 4 ] && [[ "${4:-}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            # Legacy format: check <agent> <merchant> <amount>
            check_mandate "${2:-}" "${3:-}" "${4:-}"
        else
            # New format: check <agent> <action_type> <target> [amount]
            check_action "${2:-}" "${3:-}" "${4:-}" "${5:-}"
        fi
        ;;
    check-action)
        check_action "${2:-}" "${3:-}" "${4:-}" "${5:-}"
        ;;
    log|log-action)
        log_action "${2:-}" "${3:-}" "${4:-}"
        ;;
    spend)
        spend "${2:-}" "${3:-}"
        ;;
    summary)
        summary
        ;;
    export)
        export_ledger
        ;;
    audit)
        audit_list "${2:-}"
        ;;
    audit-mandate)
        audit_for_mandate "${2:-}"
        ;;
    audit-summary)
        audit_summary "${2:-}"
        ;;
    kya-register)
        kya_register "${2:-}" "${3:-}" "${4:-}" "${5:-}"
        ;;
    kya-get)
        kya_get "${2:-}"
        ;;
    kya-list)
        kya_list
        ;;
    kya-revoke)
        kya_revoke "${2:-}" "${3:-}"
        ;;
    kill)
        kill_ledger "${*:2}"
        ;;
    unlock)
        unlock_ledger
        ;;
    *)
        echo "Agent Passport - Local Mandate Ledger v2.1.0"
        echo "Consent-gating for ALL sensitive agent actions"
        echo ""
        echo "Usage: mandate-ledger.sh <command> [args]"
        echo ""
        echo "QUICK START:"
        echo "  init                                    Initialize Agent Passport"
        echo "  templates                               List available templates"
        echo "  create-from-template <t> <agent> [args] Create mandate from template"
        echo "  create-quick <type> <agent> <csv> <ttl> Create mandate with simple syntax"
        echo ""
        echo "ACTION CATEGORIES:"
        echo "  financial     - purchases, transfers, subscriptions"
        echo "  communication - emails, messages, posts"
        echo "  data          - file deletion, edits, database writes"
        echo "  system        - shell commands, installs, config changes"
        echo "  external_api  - third-party API calls with side effects"
        echo "  identity      - public actions 'as' the user"
        echo ""
        echo "MANDATE COMMANDS:"
        echo "  create <json>              Create mandate (include action_type)"
        echo "  create-with-kya <json>     Create mandate, auto-attach agent KYA"
        echo "  get <mandate_id>           Get mandate by ID"
        echo "  list [filter]              List mandates (all|active|revoked|<action_type>)"
        echo "  revoke <mandate_id> [why]  Revoke a mandate"
        echo ""
        echo "AUTHORIZATION:"
        echo "  check-action <agent> <type> <target> [amount]"
        echo "                             Check if action is authorized"
        echo "  check <agent> <merchant> <amount>"
        echo "                             Legacy: check financial action"
        echo "  log-action <mandate_id> <amount> [description]"
        echo "                             Log action against mandate"
        echo "  spend <mandate_id> <amount>"
        echo "                             Legacy: log financial spend"
        echo ""
        echo "AUDIT:"
        echo "  audit [limit]              Show recent audit entries"
        echo "  audit-mandate <id>         Show audit for specific mandate"
        echo "  audit-summary [since]      Summary by action type"
        echo "  summary                    Show overall ledger stats"
        echo "  export                     Export full ledger as JSON"
        echo ""
        echo "KYA (Know Your Agent):"
        echo "  kya-register <agent_id> <principal> <scope> [provider]"
        echo "  kya-get <agent_id>"
        echo "  kya-list"
        echo "  kya-revoke <agent_id> [why]"
        echo ""
        echo "SAFETY:"
        echo "  kill <reason>                           Engage kill switch and freeze execution"
        echo "  unlock                                  Disengage kill switch and resume execution"
        exit 1
        ;;
esac
