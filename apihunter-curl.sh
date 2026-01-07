#!/bin/bash
# API Hunter Curl - Fixed Clean Version
# Usage: ./apihunter.sh https://target.com [wordlist.txt]

TARGET="$1"
WORDLIST="$2"

if [[ -z "$TARGET" ]]; then
    echo -e "\033[1;31mUsage: $0 <target-url> [custom-wordlist.txt]\033[0m"
    exit 1
fi

# Normalisasi URL
[[ ! "$TARGET" =~ ^http ]] && TARGET="https://$TARGET"
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter pada: $TARGET\033[0m"
echo "--------------------------------------------------------------------------------"

# Built-in paths
PATHS=(
    "" "/api" "/api/v1" "/api/v2" "/v1" "/v2" "/graphql" "/graph" "/rest" "/json" 
    "/swagger" "/swagger-ui.html" "/swagger.json" "/openapi.json" "/docs" "/redoc" 
    "/.env" "/env" "/config" "/backup" "/db" "/admin" "/auth" "/dashboard"
    "/debug" "/health" "/metrics" "/status" "/info" "/phpinfo.php"
    "/.git/HEAD" "/.git/config" "/robots.txt" "/web.config" "/actuator"
)

IDOR_BASES=(
    "/api/user/" "/api/users/" "/api/account/" "/api/profile/"
    "/user/" "/profile/" "/api/item/" "/api/order/"
)

# FIXED REGEX: Mencegah error 'invalid range end'
SECRET_REGEX='(api[-_]?key|token|secret|password|passwd|auth|bearer|aws_access_key_id|aws_secret_access_key|sk_live_|pk_live_|stripe[-_]?key|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|ya29\.|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)[\s:=]+["'\'']?[a-zA-Z0-9\-_+.=/{}/]{20,}["'\'']?'

printf "%-10s %-10s %-10s %s\n" "CODE" "SIZE" "REDIRECT" "URL"
echo "--------------------------------------------------------------------------------"

check_path() {
    local path="$1"
    local url="$TARGET$path"

    local response=$(curl -s -L --max-redirs 2 -o /dev/null -k --max-time 10 \
        -w "%{http_code}|%{size_download}|%{redirect_url}|%{url_effective}" "$url" 2>/dev/null)

    [[ -z "$response" || "$response" =~ ^000 ]] && return

    local code=$(echo "$response" | cut -d'|' -f1)
    local size=$(echo "$response" | cut -d'|' -f2)
    local redirect=$(echo "$response" | cut -d'|' -f3)
    local final_url=$(echo "$response" | cut -d'|' -f4)

    local red="NO"
    [[ -n "$redirect" && "$redirect" != "$final_url" ]] && red="YES"
    
    printf "%-10s %-10s %-10s %s\n" "$code" "$size" "$red" "$final_url"

    if [[ "$code" == "200" ]]; then
        local content=$(curl -s -k --max-time 10 "$url" 2>/dev/null)
        local is_html=false
        if echo "$content" | grep -qiE "<html|<head|<body|<title" ; then is_html=true; fi

        if echo "$path" | grep -Ei '\.env|config|backup|\.git|db|phpinfo' && [[ "$is_html" == false ]]; then
            echo -e "\033[1;31m[CRITICAL EXPOSED] $final_url\033[0m"
            echo "$content" | head -n 5
            echo ""
        elif echo "$path" | grep -Ei 'swagger|openapi|docs|redoc'; then
            echo -e "\033[1;33m[API DOCS] $final_url\033[0m"
        else
            local leaks=$(echo "$content" | grep -aiE "$SECRET_REGEX" | sort -u | head -3)
            if [[ -n "$leaks" ]]; then
                echo -e "\033[1;31m[SECRETS DETECTED] $final_url\033[0m"
                echo "$leaks"
            fi
        fi
    fi
}

# Scan built-in paths
for p in "${PATHS[@]}"; do
    check_path "$p" &
    [[ $(jobs -r -p | wc -l) -ge 10 ]] && wait -n
done
wait

# Custom wordlist
if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
    echo -e "\n\033[1;34m[+] Fuzzing Wordlist: $WORDLIST\033[0m"
    while read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        check_path "/$line" &
        [[ $(jobs -r -p | wc -l) -ge 10 ]] && wait -n
    done < "$WORDLIST"
    wait
fi

# IDOR Detection
echo -e "\n\033[1;34m[+] Checking Potential IDOR\033[0m"
echo "--------------------------------------------------------------------------------"
for base in "${IDOR_BASES[@]}"; do
    u1="${TARGET}${base}1"
    u2="${TARGET}${base}2"
    r1=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 7 "$u1" 2>/dev/null)
    r2=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 7 "$u2" 2>/dev/null)
    c1=${r1%%|*} s1=${r1#*|}
    c2=${r2%%|*} s2=${r2#*|}
    if [[ "$c1" == "200" && "$c2" == "200" && "$s1" != "$s2" ]]; then
        echo -e "\033[1;31m[IDOR VULN] $base (Size Diff: $s1 vs $s2)\033[0m"
    fi
done

echo -e "\n\033[1;32m[+] Scan Selesai!\033[0m"
