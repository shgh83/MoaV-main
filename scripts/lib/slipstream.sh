#!/bin/bash
# Slipstream QUIC-over-DNS tunnel configuration functions

SLIPSTREAM_CONFIG_DIR="/configs/slipstream"

generate_slipstream_config() {
    log_info "Setting up Slipstream configuration..."

    ensure_dir "$SLIPSTREAM_CONFIG_DIR"
    ensure_dir "$STATE_DIR/keys"

    local cert_file="$STATE_DIR/keys/slipstream-cert.pem"
    local key_file="$STATE_DIR/keys/slipstream-key.pem"

    # Generate ECDSA P-256 self-signed cert if not exists
    if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
        log_info "Generating Slipstream ECDSA P-256 certificate..."

        # Generate private key
        if ! openssl ecparam -genkey -name prime256v1 -noout -out "$key_file" 2>&1; then
            log_error "Failed to generate Slipstream private key"
            return 1
        fi

        # Generate self-signed certificate (10-year validity)
        if ! openssl req -new -x509 -key "$key_file" -out "$cert_file" \
            -days 3650 -subj "/CN=slipstream" 2>&1; then
            log_error "Failed to generate Slipstream certificate"
            return 1
        fi

        log_info "Slipstream certificate generated (valid for 10 years)"
    else
        log_info "Slipstream certificate already exists, skipping generation"
    fi

    # Verify cert/key are valid
    if [[ ! -s "$cert_file" ]]; then
        log_error "Slipstream certificate file is empty or missing"
        return 1
    fi
    if [[ ! -s "$key_file" ]]; then
        log_error "Slipstream key file is empty or missing"
        return 1
    fi

    # Copy cert to configs and outputs for distribution
    cp "$cert_file" "$SLIPSTREAM_CONFIG_DIR/cert.pem"
    ensure_dir "/outputs/slipstream"
    cp "$cert_file" "/outputs/slipstream/cert.pem"

    log_info "Slipstream configuration created"
    log_info "Certificate: $cert_file"
}

# Generate Slipstream client instructions for a user
slipstream_generate_client_instructions() {
    local user_id="$1"
    local output_dir="$2"

    local slipstream_domain="${SLIPSTREAM_SUBDOMAIN:-s}.${DOMAIN}"

    # Copy cert to user bundle
    if [[ -f "$STATE_DIR/keys/slipstream-cert.pem" ]]; then
        cp "$STATE_DIR/keys/slipstream-cert.pem" "$output_dir/slipstream-cert.pem"
    fi

    cat > "$output_dir/slipstream-instructions.txt" <<EOF
# Slipstream DNS Tunnel Instructions
# ====================================
# QUIC-over-DNS tunnel - faster than dnstt (1.5-5x speedup).
# Use when other methods are blocked. DNS tunneling works when other protocols fail.
#
# Project: https://github.com/Mygod/slipstream-rust

# Tunnel Domain:
$slipstream_domain

# Certificate: slipstream-cert.pem (included in this bundle)

# -------------------------
# Option 1: Resolver Mode (RECOMMENDED - stealthier)
# -------------------------

# Download slipstream-client from:
# https://github.com/net2share/slipstream-rust-build/releases

# Run (creates a local SOCKS5 proxy on port 1080):
slipstream-client --domain $slipstream_domain --cert slipstream-cert.pem --dns-server 1.1.1.1:53 --socks-listen 127.0.0.1:1080

# Then configure your apps to use SOCKS5 proxy: 127.0.0.1:1080

# -------------------------
# Option 2: Authoritative/Direct Mode (FASTER but less stealthy)
# -------------------------

# Connects directly to the server (bypasses DNS resolvers):
# slipstream-client --domain $slipstream_domain --cert slipstream-cert.pem --authoritative SERVER_IP:53 --socks-listen 127.0.0.1:1080

# Replace SERVER_IP with the actual server IP address.
# This mode is ~5x faster but reveals the server IP to network observers.

# -------------------------
# Alternative DNS Resolvers (if one is blocked, try another):
# -------------------------
# - Cloudflare: 1.1.1.1:53
# - Google: 8.8.8.8:53
# - Quad9: 9.9.9.9:53
# - OpenDNS: 208.67.222.222:53

# -------------------------
# Performance Notes:
# -------------------------
# - Resolver mode: ~60 KB/s (good for chat, email, light browsing)
# - Authoritative mode: ~3-4 MB/s (suitable for most tasks)
# - Use resolver mode in censored environments for stealth
# - Use authoritative mode on trusted networks for speed

# -------------------------
# Troubleshooting:
# -------------------------
# - Ensure the cert file (slipstream-cert.pem) is in the same directory
# - If resolver mode is slow, try a different DNS resolver
# - DNS tunneling works best when other methods are blocked
# - Keep slipstream-client running while you need the connection
# - Traffic exits through the MoaV server (your IP appears as server IP)
EOF

    log_info "Generated Slipstream instructions for $user_id"
}
