#!/bin/bash
# API Hunter Upgraded - Pure Curl with Better Detection
# Usage: ./apihunter-upgraded.sh <https://target.com> [wordlist.txt]
# Wordlist opsional: file txt dengan satu path per baris untuk fuzzing tambahan

TARGET="$1"
WORDLIST="$2"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url> [custom-wordlist.txt]"
    echo "Contoh: $0 https://example.com apis.txt"
    exit 1
fi

[[ ! "$TARGET" =~ ^http ]] && TARGET="https://$TARGET"
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter Upgraded pada: $TARGET\033[0m"
echo "=================================================="

# Daftar paths built-in yang lebih lengkap
PATHS=(
    "" "/api" "/api/v1" "/api/v2" "/api/v3" "/v1" "/v2" "/v3" "/graphql" "/graph"
    "/rest" "/json" "/ws" "/websocket" "/socket.io"
    "/swagger" "/swagger-ui.html" "/swagger.json" "/swagger/v1/swagger.json"
    "/openapi.json" "/docs" "/redoc" "/api-docs" "/apidoc"
    "/.env" "/env" "/config" "/backup" "/db" "/admin" "/login" "/auth" "/dashboard"
    "/debug" "/health" "/healthz" "/ping" "/metrics" "/status" "/info" "/version" "/phpinfo.php"
    "/.git/HEAD" "/.git/config" "/robots.txt" "/sitemap.xml" "/web.config"
    "/server-status" "/actuator" "/trace" "/env.js" "/config.json"
    "/users" "/accounts" "/profile" "/settings" "/me"
)

# Tambah IDOR base paths lebih banyak
IDOR_BASES=(
    "/api/user/" "/api/users/" "/api/account/" "/api/profile/"
    "/user/" "/profile/" "/api/item/" "/api/order/" "/api/post/"
)

# Regex secrets lebih komprehensif
SECRET_REGEX='(?i)(api[_-]?key|token|secret|password|passwd|auth|bearer|aws_access_key_id|aws_secret_access_key|sk_live_|pk_live_|stripe[_-]?key|firebase|heroku|slack|discord|jwt|private[_-]?key|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|ya29\.[0-9a-zA-Z\-_]+|AIza[0-9A-Za-z\-_]{35}|sq0.[0-9a-zA-Z\-_]+|EAI.[0-9A-Za-z\-_]{30,}|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)[\s:=]+["'\''`]?[a-zA-Z0-9\-_+.=/{}/]{20,}["'\''`]?'

# Header tabel
printf "%-10s %-8s %-10s %s\n" "HTTP CODE" "SIZE" "REDIRECT?" "URL"
echo "---------------------------------------------------------------"

# Fungsi untuk check path
check_path() {
    local path="$1"
    local url="$TARGET$path"
    local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}|%{url_effective}" -k -m 15 --max-redirs 5 "$url")
    local code=$(echo "$response" | cut -d'|' -f1)
    local size=$(echo "$response" | cut -d'|' -f2)
    local redirect=$(echo "$response" | cut -d'|' -f3)
    local final_url=$(echo "$response" | cut -d'|' -f4)

    if [[ "$code" == "000" ]]; then return; fi

    # Print ringkasan tabel
    if [[ -n "$redirect" ]]; then redirect="YES"; else redirect="NO"; fi
    printf "%-10s %-8s %-10s %s\n" "$code" "$size" "$redirect" "$final_url"

    # Highlight temuan kritis
    if [[ "$code" == "200" ]]; then
        local content=$(curl -s -k "$url" --max-time 15)

        # Critical exposed files
        if echo "$path" | grep -Ei '\.env|config|backup|\.git|db|phpinfo'; then
            echo -e "\033[1;31m[CRITICAL EXPOSED] $final_url (SIZE: $size bytes)\033[0m"
            echo "$content" | head -20
            echo

        # API Docs
        elif echo "$path" | grep -Ei 'swagger|openapi|docs|redoc'; then
            echo -e "\033[1;33m[API DOCUMENTATION FOUND] $final_url\033[0m"

        # Potential debug/admin
        elif echo "$path" | grep -Ei 'debug|admin|actuator|trace|metrics|health'; then
            echo -e "\033[1;35m[POTENTIAL EXPOSED PANEL/DEBUG] $final_url\033[0m"

        # Secrets leak detection
        else
            local leaks=$(echo "$content" | grep -aioE "$SECRET_REGEX" | sort -u | head -10)
            if [[ -n "$leaks" ]]; then
                echo -e "\033[1;31m[SECRETS LEAK DETECTED] $final_url\033[0m"
                echo "$leaks"
                echo
            fi
        fi

    elif [[ "$code" == "401" || "$code" == "403" ]]; then
        echo -e "\033[1;36m[PROTECTED - AUTH REQUIRED] $code → $final_url\033[0m"
    elif [[ "$code" == "301" || "$code" == "302" ]]; then
        echo -e "\033[1;32m[REDIRECT] $code → $final_url (to $redirect)\033[0m"
    fi
}

# Scan built-in paths (parallel untuk cepat)
for path in "${PATHS[@]}"; do
    check_path "$path" &
done

# Jika ada custom wordlist, scan juga
if [[ -f "$WORDLIST" ]]; then
    echo -e "\033[1;34m[+] Fuzzing dengan custom wordlist: $WORDLIST\033[0m"
    while read -r custom_path; do
        [[ -z "$custom_path" || "$custom_path" =~ ^# ]] && continue
        check_path "$custom_path" &
    done < "$WORDLIST"
fi

wait  # Tunggu semua background process selesai

# IDOR Detection Upgraded
echo -e "\n\033[1;34m[+] Memulai Deteksi Potensi IDOR (Lebih Banyak Base)\033[0m"
echo "=================================================="

for base in "${IDOR_BASES[@]}"; do
    url1="$TARGET$base""1"
    url2="$TARGET$base""2"
    url_rand1="$TARGET$base""$((RANDOM % 900000 + 100000))"
    url_rand2="$TARGET$base""$((RANDOM % 900000 + 100000))"

    resp1=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k -m 10 "$url1")
    resp2=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k -m 10 "$url2")
    resp_r1=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k -m 10 "$url_rand1")

    code1=$(echo "$resp1" | cut -d'|' -f1)
    size1=$(echo "$resp1" | cut -d'|' -f2)
    code2=$(echo "$resp2" | cut -d'|' -f1)
    size2=$(echo "$resp2" | cut -d'|' -f2)
    code_r=$(echo "$resp_r1" | cut -d'|' -f1)
    size_r=$(echo "$resp_r1" | cut -d'|' -f2)

    content1=$(curl -s -k "$url1" | head -c 500)
    content2=$(curl -s -k "$url2" | head -c 500)

    if [[ "$code1" == "200" && "$code2" == "200" && "$content1" != "$content2" && "$size1" != "$size2" ]]; then
        echo -e "\033[1;31m[POTENSI IDOR TINGGI] $base → ID 1 & 2 berbeda konten (size: $size1 vs $size2)\033[0m"
        echo "Snippet ID1: ${content1:0:150}..."
        echo "Snippet ID2: ${content2:0:150}..."
        echo
    elif [[ "$code1" == "200" && "$code_r" == "200" ]]; then
        echo -e "\033[1;33m[POTENSI OPEN ACCESS] ID random $url_rand1 berhasil (size: $size_r)\033[0m"
    fi
done

echo -e "\033[1;32m[+] Scan selesai! Gunakan dengan bijak & hanya pada target yang diizinkan.\033[0m"
