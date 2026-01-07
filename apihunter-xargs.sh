#!/bin/bash
# API Hunter Ultra Fast - Pure Curl + xargs High Concurrency
# Usage: ./apihunter-xargs.sh <https://target.com> [custom-wordlist.txt] [threads]
# Contoh: ./apihunter-xargs.sh https://example.com apis.txt 30

TARGET="$1"
WORDLIST="$2"
THREADS="${3:-20}"  # Default 20 concurrent processes, ubah sesuka

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url> [wordlist.txt] [threads]"
    echo "Contoh: $0 https://example.com apis.txt 50"
    exit 1
fi

[[ ! "$TARGET" =~ ^http ]] && TARGET="https://$TARGET"
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter Ultra Fast pada: $TARGET\033[0m"
echo -e "\033[1;34m[+] Concurrency: $THREADS threads (xargs -P)\033[0m"
echo "=================================================="

# Built-in paths
mapfile -t BUILTIN_PATHS <<EOF
/
/api
/api/v1
/api/v2
/api/v3
/v1
/v2
/v3
/graphql
/graph
/rest
/json
/ws
/websocket
/socket.io
/swagger
/swagger-ui.html
/swagger.json
/swagger/v1/swagger.json
/openapi.json
/docs
/redoc
/api-docs
/apidoc
/.env
/env
/config
/backup
/db
/admin
/login
/auth
/dashboard
/debug
/health
/healthz
/ping
/metrics
/status
/info
/version
/phpinfo.php
/.git/HEAD
/.git/config
/robots.txt
/sitemap.xml
/web.config
/server-status
/actuator
/trace
/env.js
/config.json
/users
/accounts
/profile
/settings
/me
EOF

# Regex secrets komprehensif
SECRET_REGEX='(?i)(api[_-]?key|token|secret|password|passwd|auth|bearer|aws_access_key_id|aws_secret_access_key|sk_live_|pk_live_|stripe[_-]?key|firebase|heroku|slack|discord|jwt|private[_-]?key|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|ya29\.[0-9a-zA-Z\-_]+|AIza[0-9A-Za-z\-_]{35}|sq0.[0-9a-zA-Z\-_]+|EAI.[0-9A-Za-z\-_]{30,}|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)[\s:=]+["'\''`]?[a-zA-Z0-9\-_+.=/{}/]{20,}["'\''`]?'

# Header tabel
printf "%-10s %-10s %-10s %s\n" "CODE" "SIZE" "REDIRECT" "URL"
echo "--------------------------------------------------------------------------------"

# Fungsi check satu path (dipanggil oleh xargs)
check_path() {
    local path="$1"
    local url="$TARGET$path"
    local out=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}|%{url_effective}" -k --max-time 15 --max-redirs 5 "$url" 2>/dev/null)

    [[ -z "$out" || "$out" == "000|"* ]] && return

    local code=$(echo "$out" | cut -d'|' -f1)
    local size=$(echo "$out" | cut -d'|' -f2)
    local redirect=$(echo "$out" | cut -d'|' -f3)
    local final_url=$(echo "$out" | cut -d'|' -f4)

    # Print ringkasan langsung
    if [[ -n "$redirect" ]]; then red="YES"; else red="NO"; fi
    printf "%-10s %-10s %-10s %s\n" "$code" "$size" "$red" "$final_url"

    # Highlight temuan penting (hanya untuk 200)
    if [[ "$code" == "200" ]]; then
        local content=$(curl -s -k --max-time 15 "$url")

        if echo "$path" | grep -Ei '\.env|config|backup|\.git|db|phpinfo'; then
            echo -e "\033[1;31m[CRITICAL EXPOSED] $final_url (SIZE: $size)\033[0m"
            echo "$content" | head -20
            echo

        elif echo "$path" | grep -Ei 'swagger|openapi|docs|redoc'; then
            echo -e "\033[1;33m[API DOCS FOUND] $final_url\033[0m"

        elif echo "$path" | grep -Ei 'debug|admin|actuator|trace|metrics|health'; then
            echo -e "\033[1;35m[POTENTIAL EXPOSED] $final_url\033[0m"

        else
            local leaks=$(echo "$content" | grep -aioE "$SECRET_REGEX" | sort -u | head -10)
            if [[ -n "$leaks" ]]; then
                echo -e "\033[1;31m[SECRETS LEAK] $final_url\033[0m"
                echo "$leaks"
                echo
            fi
        fi

    elif [[ "$code" == "401" || "$code" == "403" ]]; then
        echo -e "\033[1;36m[PROTECTED] $code → $final_url\033[0m"

    elif [[ "$code" == "301" || "$code" == "302" ]]; then
        echo -e "\033[1;32m[REDIRECT] $code → $final_url → $redirect\033[0m"
    fi
}

# Export fungsi dan variabel agar bisa dipakai oleh xargs
export -f check_path
export TARGET SECRET_REGEX

# Jalankan semua built-in paths secara parallel
printf "%s\n" "${BUILTIN_PATHS[@]}" | xargs -P "$THREADS" -I {} bash -c 'check_path "{}"'

# Jika ada custom wordlist, proses juga secara parallel
if [[ -f "$WORDLIST" ]]; then
    echo -e "\033[1;34m[+] Fuzzing custom wordlist: $WORDLIST (parallel $THREADS threads)\033[0m"
    grep -v '^#' "$WORDLIST" | grep -v '^$' | xargs -P "$THREADS" -I {} bash -c 'check_path "{}"'
fi

# IDOR Detection (sequential, lebih akurat)
echo -e "\n\033[1;34m[+] Deteksi Potensi IDOR\033[0m"
echo "=================================================="

IDOR_BASES=("/api/user/" "/api/users/" "/api/account/" "/api/profile/" "/user/" "/profile/" "/api/item/" "/api/order/" "/api/post/")

for base in "${IDOR_BASES[@]}"; do
    url1="$TARGET$base"1
    url2="$TARGET$base"2
    rand_id=$((RANDOM % 900000 + 100000))
    url_rand="$TARGET$base$rand_id"

    resp1=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url1")
    resp2=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url2")
    resp_r=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url_rand")

    code1=${resp1%%|*}  size1=${resp1#*|}
    code2=${resp2%%|*}  size2=${resp2#*|}
    code_r=${resp_r%%|*} size_r=${resp_r#*|}

    if [[ "$code1" == "200" && "$code2" == "200" && "$size1" != "$size2" ]]; then
        content1=$(curl -s -k "$url1" | head -c 300)
        content2=$(curl -s -k "$url2" | head -c 300)
        echo -e "\033[1;31m[POTENSI IDOR TINGGI] $base → ID 1 ($size1 bytes) vs ID 2 ($size2 bytes)\033[0m"
        echo "Snippet ID1: ${content1}..."
        echo "Snippet ID2: ${content2}..."
        echo
    elif [[ "$code1" == "200" && "$code_r" == "200" ]]; then
        echo -e "\033[1;33m[POTENSI OPEN ACCESS] ID random $rand_id berhasil ($size_r bytes)\033[0m"
    fi
done

echo -e "\033[1;32m[+] Scan selesai! Total threads digunakan: $THREADS\033[0m"
echo -e "\033[1;32m[+] Gunakan hanya pada target yang kamu punya izin ya!\033[0m"
