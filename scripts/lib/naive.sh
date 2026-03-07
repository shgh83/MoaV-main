#!/bin/bash
# NaiveProxy and Shadowsocks 2022 credential generation functions

# Generate NaiveProxy user credentials
generate_naive_config() {
    log_info "Setting up NaiveProxy credentials..."

    ensure_dir "$STATE_DIR/keys"
    local pass_file="$STATE_DIR/keys/naive.password"
    local user_file="$STATE_DIR/keys/naive.user"

    # Write user (defaults to "naive" unless operator set NAIVE_USER)
    local user="${NAIVE_USER:-naive}"
    echo "$user" > "$user_file"

    if [[ -n "${NAIVE_PASS:-}" ]]; then
        echo "$NAIVE_PASS" > "$pass_file"
        log_info "NaiveProxy password loaded from env var"
    elif [[ -f "$pass_file" ]] && [[ -s "$pass_file" ]]; then
        log_info "NaiveProxy password already exists, skipping generation"
    else
        openssl rand -base64 24 | tr -d '=+/' | head -c 32 > "$pass_file"
        log_info "NaiveProxy password generated: $pass_file"
    fi

    export NAIVE_USER="$user"
    export NAIVE_PASS
    NAIVE_PASS=$(cat "$pass_file" | tr -d '\n\r ')
    log_info "NaiveProxy user: $NAIVE_USER"
}

# Generate Shadowsocks 2022 password (32 raw bytes, base64-encoded)
generate_ss_config() {
    log_info "Setting up Shadowsocks 2022 credentials..."

    ensure_dir "$STATE_DIR/keys"
    local pass_file="$STATE_DIR/keys/ss2022.password"

    if [[ -n "${SS_PASSWORD:-}" ]]; then
        echo "$SS_PASSWORD" > "$pass_file"
        log_info "Shadowsocks password loaded from env var"
    elif [[ -f "$pass_file" ]] && [[ -s "$pass_file" ]]; then
        log_info "Shadowsocks 2022 password already exists, skipping generation"
    else
        # 2022-blake3-aes-256-gcm requires a 32-byte key, base64-encoded
        openssl rand -base64 32 > "$pass_file"
        log_info "Shadowsocks 2022 password generated: $pass_file"
    fi

    export SS_PASSWORD
    SS_PASSWORD=$(cat "$pass_file" | tr -d '\n\r ')
    log_info "Shadowsocks 2022 method: 2022-blake3-aes-256-gcm"
}
