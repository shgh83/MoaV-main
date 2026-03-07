#!/bin/bash
# Knocker key and keypair generation functions

# Generate knocker HMAC secret and dnstt-ssh ED25519 keypair
generate_knocker_config() {
    log_info "Setting up Knocker configuration..."

    ensure_dir "$STATE_DIR/keys"
    local secret_file="$STATE_DIR/keys/knocker.secret"

    if [[ -n "${KNOCKER_SECRET:-}" ]]; then
        # Use operator-supplied secret
        echo "$KNOCKER_SECRET" > "$secret_file"
        log_info "Knocker secret loaded from env var (${#KNOCKER_SECRET} chars)"
    elif [[ -f "$secret_file" ]] && [[ -s "$secret_file" ]]; then
        log_info "Knocker secret already exists, skipping generation"
    else
        # Generate 32-byte random hex secret
        openssl rand -hex 32 > "$secret_file"
        log_info "Knocker HMAC secret generated: $secret_file"
    fi

    local secret
    secret=$(cat "$secret_file" | tr -d '\n\r ')

    # Compute current token for display
    local window
    window=$(( $(date +%s) / 300 ))
    local token
    token=$(echo -n "$window" | openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | od -An -tx1 | tr -d ' \n' | cut -c1-32 || echo "generation-failed")

    log_info "Knocker secret: $secret_file ($(wc -c < "$secret_file" | tr -d ' ') bytes)"
    log_info "Current token  (first 16 bytes of HMAC): $token"
    log_info "Token rotates every 5 minutes"

    # Export so docker-compose bootstrap env includes it
    export KNOCKER_SECRET="$secret"
}

# Generate SSH ED25519 keypair for dnstt-ssh tunnel
generate_dnstt_ssh_keypair() {
    log_info "Setting up dnstt-ssh keypair..."

    ensure_dir "$STATE_DIR/keys"
    local key_file="$STATE_DIR/keys/dnstt-ssh-id_ed25519"
    local pub_file="$STATE_DIR/keys/dnstt-ssh-authorized_keys"

    if [[ -f "$key_file" ]] && [[ -f "$pub_file" ]]; then
        log_info "dnstt-ssh keypair already exists, skipping generation"
        return 0
    fi

    # Generate ED25519 keypair
    ssh-keygen -t ed25519 -f "$key_file" -N "" -C "moav-dnstt-ssh" -q
    cp "${key_file}.pub" "$pub_file"

    log_info "dnstt-ssh ED25519 keypair generated:"
    log_info "  Private key : $key_file (share to clients)"
    log_info "  Public key  : $pub_file (placed in authorized_keys)"
    log_info ""
    log_info "Client SSH command (through DNS tunnel):"
    log_info "  ssh -i dnstt-ssh-id_ed25519 -N -D 1080 -p 2222 tunnel@127.0.0.1"

    # Copy to outputs for distribution
    ensure_dir "/outputs/dnstt-ssh"
    cp "$key_file" "/outputs/dnstt-ssh/id_ed25519"
    chmod 600 "/outputs/dnstt-ssh/id_ed25519"
    cp "${key_file}.pub" "/outputs/dnstt-ssh/id_ed25519.pub"

    cat > "/outputs/dnstt-ssh/ssh-instructions.txt" <<EOF
# dnstt-ssh Instructions
# ======================
# SSH access through the DNS tunnel — works even when ALL other ports are blocked.
#
# Step 1: Set up dnstt-client (creates local TCP port forwarded through DNS):
#
#   dnstt-client -doh https://1.1.1.1/dns-query -pubkey DNSTT_PUBKEY t.DOMAIN 127.0.0.1:2222
#
#   (Replace DNSTT_PUBKEY and DOMAIN from your dnstt-instructions.txt)
#
# Step 2: Connect SSH with SOCKS5 dynamic forwarding:
#
#   ssh -i id_ed25519 -N -D 1080 -p 2222 tunnel@127.0.0.1
#
# Step 3: Configure apps to use SOCKS5 proxy: 127.0.0.1:1080
#
# Notes:
#   - Keep both dnstt-client AND ssh running simultaneously
#   - Throughput: ~10-50 KB/s (DNS tunnel speed limit)
#   - The id_ed25519 private key in this bundle is UNIQUE to your server
#   - Protect it like a password
EOF
}

# Generate DNS TXT record value for current knocker token (for publishing)
knocker_current_dns_token() {
    local secret_file="$STATE_DIR/keys/knocker.secret"
    if [[ ! -f "$secret_file" ]]; then
        echo ""
        return
    fi
    local secret
    secret=$(cat "$secret_file" | tr -d '\n\r ')
    local window
    window=$(( $(date +%s) / 300 ))
    # 16-byte HMAC prefix, base64url-encoded
    echo -n "$window" | openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | \
        head -c 16 | base64 | tr '+/' '-_' | tr -d '='
}
