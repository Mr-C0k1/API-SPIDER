#!/bin/bash
# API Hunter Curl - Fixed SSL Errors & Stable (Pure Curl Recon)
# Usage: ./apihunter-curl.sh https://target.com [wordlist.txt]
# Contoh: ./apihunter-curl.sh https://example.com apis.txt

TARGET="$1"
WORDLIST="$2"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url> [custom-wordlist.txt]"
    echo "Contoh: $0 https://example.com apis.txt"
    exit 1
fi

# Tambah https jika belum ada
if [[ ! "$TARGET" =~ ^http ]]; then
    TARGET="https://$TARGET"
fi
# Hilangkan trailing slash
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter Curl pada: $TARGET\033[0m"
echo "=================================================="

# Built-in paths
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

# IDOR bases
IDOR_BASES=(
    "/api/user/" "/api/users/" "/api/account/" "/api/profile/"
    "/user/" "/profile/" "/api/item/" "/api/order/" "/api/post/"
)

# Regex secrets (diperbaiki, simplified untuk avoid quote errors)
SECRET_REGEX='(api[_-]?key|token|secret|password|auth|bearer|aws_access_key|sk_live_|pk_live_|stripe[_-]?key|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9-_=]+)[\s:=]+[a-zA-Z0-9\-_]{20,}'

# Header tabel
printf "%-10s %-10s %-10s %s\n" "CODE" "SIZE" "REDIRECT" "URL"
echo "--------------------------------------------------------------------------------"

# Fungsi check path (fixed SSL dengan -k always, error handling)
check_path() {
    local path="$1"
    local url="$TARGET$path"
    
    # Curl header only, dengan -k untuk bypass SSL errors
    local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}|%{url_effective}" \
                         -k --max-time 15 --max-redirs 5 "$url" 2>/dev/null)
    
    if [[ -z "$response" || "$response" =~ ^000 ]]; then
        echo -e "\033[1;31m[SKIP] Timeout/SSL Error on $url\033[0m"
        return
    fi
    
    local code=$(echo "$response" | cut -d'|' -f1)
    local size=$(echo "$response" | cut -d'|' -f2)
    local redirect=$(echo "$response" | cut -d'|' -f3)
    local final_url=$(echo "$response" | cut -d'|' -f4)
    
    # Tabel output
    if [[ -n "$redirect" && "$redirect" != "$final_url" ]]; then
        local red="YES"
    else
        local red="NO"
    fi
    printf "%-10s %-10s %-10s %s\n" "$code" "$size" "$red" "$final_url"

    # Highlight hanya untuk 200
    if [[ "$code" == "200" ]]; then
        local content=$(curl -s -k --max-time 15 "$url" 2>/dev/null)
        
        if echo "$path" | grep -Ei '\.env|config|backup|\.git|db|phpinfo'; then
            echo -e "\033[1;31m[CRITICAL EXPOSED] $final_url (SIZE: ${size} bytes)\033[0m"
            echo "$content" | head -n 20
            echo ""
            
        elif echo "$path" | grep -Ei 'swagger|openapi|docs|redoc'; then
            echo -e "\033[1;33m[API DOCS FOUND] $final_url\033[0m"
            
        elif echo "$path" | grep -Ei 'debug|admin|actuator|trace|metrics|health'; then
            echo -e "\033[1;35m[POTENTIAL EXPOSED] $final_url\033[0m"
            
        else
            local leaks=$(echo "$content" | grep -aiE "$SECRET_REGEX" | sort -u | head -10)
            if [[ -n "$leaks" ]]; then
                echo -e "\033[1;31m[SECRETS LEAK] $final_url\033[0m"
                echo "$leaks"
                echo ""
            fi
        fi
        
    elif [[ "$code" == "401" || "$code" == "403" ]]; then
        echo -e "\033[1;36m[PROTECTED] $code → $final_url\033[0m"
        
    elif [[ "$code" == "301" || "$code" == "302" ]]; then
        echo -e "\033[1;32m[REDIRECT] $code → $final_url → $redirect\033[0m"
    fi
}

# Export untuk background jobs
export -f check_path
export TARGET SECRET_REGEX

# Scan built-in (parallel, max 10 jobs agar tidak overload)
for path in "${PATHS[@]}"; do
    check_path "$path" &
    if [[ $(jobs -r -p | wc -l) -ge 10 ]]; then wait -n; fi
done

# Custom wordlist
if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
    echo -e "\033[1;34m[+] Fuzzing wordlist: $WORDLIST\033[0m"
    grep -v '^#' "$WORDLIST" | grep -v '^$' | while read -r custom_path; do
        check_path "$custom_path" &
        if [[ $(jobs -r -p | wc -l) -ge 10 ]]; then wait -n; fi
    done
fi

wait

# IDOR Detection (fixed, dengan -k)
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

    local code1="${r1%%|*}"
    local size1="${r1#*|}"
    local code2="${r2%%|*}"
    local size2="${r2#*|}"
    local code_r="${rr%%|*}"
    local size_r="${rr#*|}"

    if [[ "$code1" == "200" && "$code2" == "200" && "$size1" != "$size2" ]]; then
        local snippet1=$(curl -s -k "$url1" 2>/dev/null | head -c 300 | strings 2>/dev/null)
        local snippet2=$(curl -s -k "$url2" 2>/dev/null | head -c 300 | strings 2>/dev/null)
        
        echo -e "\033[1;31m[POTENSI IDOR] ${base} → ID 1 vs ID 2 berbeda (size: $size1 vs $size2)\033[0m"
        echo "  Snippet 1: ${snippet1:0:150}..."
        echo "  Snippet 2: ${snippet2:0:150}..."
        echo ""
    elif [[ "$code1" == "200" && "$code_r" == "200" ]]; then
        echo -e "\033[1;33m[OPEN ACCESS] ID random $rand_id di ${base} (size: $size_r)\033[0m"
    fi
done

echo -e "\033[1;32m[+] Scan selesai! Hasil nyata dari target (SSL bypassed).\033[0m"
echo -e "\033[1;37m[+] Ethical use only! Jika error persist, update ca-certificates: sudo apt update && sudo apt install ca-certificates\033[0m"
