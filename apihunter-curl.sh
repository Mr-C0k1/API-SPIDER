#!/bin/bash
# API Hunter Curl - Final Fixed Version (No False Positive Critical)
# Usage: ./apihunter-curl.sh https://target.com [wordlist.txt]

TARGET="$1"
WORDLIST="$2"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url> [custom-wordlist.txt]"
    echo "Contoh: $0 https://example.com apis.txt"
    exit 1
fi

# Tambah https jika belum ada
[[ ! "$TARGET" =~ ^http ]] && TARGET="https://$TARGET"
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter Curl pada: $TARGET\033[0m"
echo "=================================================="

# Built-in paths (bersih dari markdown)
PATHS=(
    "" "/api" "/api/v1" "/api/v2" "/api/v3" "/v1" "/v2" "/v3"
    "/graphql" "/graph" "/rest" "/json" "/ws" "/websocket" "/socket.io"
    "/swagger" "/swagger-ui.html" "/swagger.json" "/swagger/v1/swagger.json"
    "/openapi.json" "/docs" "/redoc" "/api-docs" "/apidoc"
    "/.env" "/env" "/config" "/backup" "/db" "/admin" "/login" "/auth" "/dashboard"
    "/debug" "/health" "/healthz" "/ping" "/metrics" "/status" "/info" "/version" "/phpinfo.php"
    "/.git/HEAD" "/.git/config" "/robots.txt" "/sitemap.xml" "/web.config"
    "/server-status" "/actuator" "/trace" "/env.js" "/config.json"
    "/users" "/accounts" "/profile" "/settings" "/me"
)

IDOR_BASES=(
    "/api/user/" "/api/users/" "/api/account/" "/api/profile/"
    "/user/" "/profile" "/api/item/" "/api/order/" "/api/post/"
)

# Regex secrets lebih akurat
SECRET_REGEX='(api[_-]?key|token|secret|password|passwd|auth|bearer|aws_access_key_id|aws_secret_access_key|sk_live_|pk_live_|stripe[_-]?key|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|ya29\.|AIza[0-9A-Za-z\-_]{35}|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)[\s:=]+["'\''`]?[a-zA-Z0-9\-_+.=/{}/]{20,}["'\''`]?'

printf "%-10s %-10s %-10s %s\n" "CODE" "SIZE" "REDIRECT" "URL"
echo "--------------------------------------------------------------------------------"

check_path() {
    local path="$1"
    local url="$TARGET$path"

    local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}|%{url_effective}" \
                         -k --max-time 15 --max-redirs 5 "$url" 2>/dev/null)

    [[ -z "$response" || "$response" =~ ^000 ]] && return

    local code=$(echo "$response" | cut -d'|' -f1)
    local size=$(echo "$response" | cut -d'|' -f2)
    local redirect=$(echo "$response" | cut -d'|' -f3)
    local final_url=$(echo "$response" | cut -d'|' -f4)

    [[ -n "$redirect" && "$redirect" != "$final_url" ]] && local red="YES" || local red="NO"
    printf "%-10s %-10s %-10s %s\n" "$code" "$size" "$red" "$final_url"

    if [[ "$code" == "200" ]]; then
        local content=$(curl -s -k --max-time 15 "$url" 2>/dev/null)

        # Cek apakah content mirip HTML biasa (false positive)
        if echo "$content" | grep -qiE "<html|<head|<body|<title|<!DOCTYPE html"; then
            local is_html=true
        else
            local is_html=false
        fi

        # Critical exposed: hanya jika path sensitif DAN bukan HTML biasa
        if echo "$path" | grep -Ei '\.env|config|backup|\.git|db|phpinfo'; then
            if [[ "$is_html" == false ]]; then
                echo -e "\033[1;31m[CRITICAL EXPOSED - REAL] $final_url (SIZE: $size bytes)\033[0m"
                echo "$content" | head -n 20
                echo
            else
                echo -e "\033[1;33m[INFO] $final_url → HTML biasa (bukan config asli)\033[0m"
            fi

        elif echo "$path" | grep -Ei 'swagger|openapi|docs|redoc'; then
            echo -e "\033[1;33m[API DOCS FOUND] $final_url\033[0m"

        elif echo "$path" | grep -Ei 'debug|admin|actuator|trace|metrics|health'; then
            echo -e "\033[1;35m[POTENTIAL EXPOSED] $final_url\033[0m"

        else
            local leaks=$(echo "$content" | grep -aiE "$SECRET_REGEX" | sort -u | head -10)
            if [[ -n "$leaks" ]]; then
                echo -e "\033[1;31m[SECRETS LEAK DETECTED] $final_url\033[0m"
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

export -f check_path
export TARGET SECRET_REGEX

# Scan built-in (max 15 parallel)
for path in "${PATHS[@]}"; do
    check_path "$path" &
    [[ $(jobs -r -p | wc -l) -ge 15 ]] && wait -n
done

# Custom wordlist
if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
    echo -e "\033[1;34m[+] Fuzzing wordlist: $WORDLIST\033[0m"
    grep -v '^#' "$WORDLIST" | grep -v '^$' | while read -r p; do
        check_path "$p" &
        [[ $(jobs -r -p | wc -l) -ge 15 ]] && wait -n
    done
fi

wait

# IDOR Detection
echo -e "\n\033[1;34m[+] Deteksi Potensi IDOR\033[0m"
echo "=================================================="
for base in "${IDOR_BASES[@]}"; do
    local url1="${TARGET}${base}1"
    local url2="${TARGET}${base}2"
    local rand_id=$((RANDOM % 900000 + 100000))
    local url_rand="${TARGET}${base}${rand_id}"

    local r1=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url1" 2>/dev/null || echo "000|0")
    local r2=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url2" 2>/dev/null || echo "000|0")
    local rr=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url_rand" 2>/dev/null || echo "000|0")

    local code1=${r1%%|*} size1=${r1#*|}
    local code2=${r2%%|*} size2=${r2#*|}
    local code_r=${rr%%|*} size_r=${rr#*|}

    if [[ "$code1" == "200" && "$code2" == "200" && "$size1" != "$size2" ]]; then
        echo -e "\033[1;31m[POTENSI IDOR] ${base} → ID 1 vs 2 berbeda (size: $size1 ≠ $size2)\033[0m"
    elif [[ "$code1" == "200" && "$code_r" == "200" ]]; then
        echo -e "\033[1;33m[OPEN ACCESS] ID random $rand_id berhasil di ${base}\033[0m"
    fi
done

echo -e "\033[1;32m[+] Scan selesai! False positive critical sudah diminimalisir.\033[0m"
echo -e "\033[1;37m[+] Gunakan hanya pada target berizin. Stay ethical!\033[0m"
