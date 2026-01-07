#!/bin/bash
# API Hunter Upgraded - Fixed & Stable Version
# Usage: ./apihunter-fixed.sh https://target.com [wordlist.txt]
# Contoh: ./apihunter-fixed.sh https://example.com apis.txt

TARGET="$1"
WORDLIST="$2"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url> [custom-wordlist.txt]"
    echo "Contoh: $0 https://example.com apis.txt"
    exit 1
fi

# Tambah https jika belum ada
[[ ! "$TARGET" =~ ^http ]] && TARGET="https://$TARGET"
# Hilangkan trailing slash
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter Fixed pada: $TARGET\033[0m"
echo "=================================================="

# Built-in paths yang lebih lengkap dan bersih
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

# Base paths untuk IDOR testing
IDOR_BASES=(
    "/api/user/" "/api/users/" "/api/account/" "/api/profile/"
    "/user/" "/profile/" "/api/item/" "/api/order/" "/api/post/"
)

# Regex secrets yang kuat
SECRET_REGEX='(?i)(api[_-]?key|token|secret|password|passwd|auth|bearer|aws_access_key_id|aws_secret_access_key|sk_live_|pk_live_|stripe[_-]?key|firebase|heroku|slack|discord|jwt|private[_-]?key|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|ya29\.[0-9a-zA-Z\-_]+|AIza[0-9A-Za-z\-_]{35}|sq0.[0-9a-zA-Z\-_]+|EAI.[0-9A-Za-z\-_]{30,}|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)[\s:=]+["'`'"'"']?[a-zA-Z0-9\-_+.=/{}/]{20,}[\"'`'"'"']?'

# Header tabel hasil
printf "%-10s %-10s %-10s %s\n" "CODE" "SIZE" "REDIRECT" "URL"
echo "--------------------------------------------------------------------------------"

# Fungsi check satu path
check_path() {
    local path="$1"
    local url="$TARGET$path"
    
    # Request ringan dulu untuk header only
    local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}|%{url_effective}" \
                         -k --max-time 15 --max-redirs 5 "$url" 2>/dev/null)
    
    # Jika timeout atau error curl
    [[ -z "$response" || "$response" =~ ^000 ]] && return
    
    local code=$(echo "$response" | cut -d'|' -f1)
    local size=$(echo "$response" | cut -d'|' -f2)
    local redirect=$(echo "$response" | cut -d'|' -f3)
    local final_url=$(echo "$response" | cut -d'|' -f4)
    
    # Tampilkan di tabel
    if [[ -n "$redirect" && "$redirect" != "$final_url" ]]; then
        red="YES"
    else
        red="NO"
    fi
    printf "%-10s %-10s %-10s %s\n" "$code" "$size" "$red" "$final_url"

    # Highlight temuan penting hanya untuk status 200
    if [[ "$code" == "200" ]]; then
        local content=$(curl -s -k --max-time 15 "$url")
        
        if echo "$path" | grep -Ei '\.env|config|backup|\.git|db|phpinfo'; then
            echo -e "\033[1;31m[CRITICAL EXPOSED] $final_url (SIZE: $size bytes)\033[0m"
            echo "$content" | head -n 20
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

# Export fungsi dan variabel untuk background jobs
export -f check_path
export TARGET SECRET_REGEX

# Scan built-in paths secara paralel (cepat)
for path in "${PATHS[@]}"; do
    check_path "$path" &
done

# Scan custom wordlist jika ada
if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
    echo -e "\033[1;34m[+] Fuzzing custom wordlist: $WORDLIST\033[0m"
    grep -v '^#' "$WORDLIST" | grep -v '^$' | while read -r custom_path; do
        check_path "$custom_path" &
    done
fi

# Tunggu semua proses selesai
wait

# === IDOR Detection (diperbaiki total) ===
echo -e "\n\033[1;34m[+] Memulai Deteksi Potensi IDOR\033[0m"
echo "=================================================="

for base in "${IDOR_BASES[@]}"; do
    # Gunakan ${base} agar aman dari karakter /
    local url1="${TARGET}${base}1"
    local url2="${TARGET}${base}2"
    local rand_id=$((RANDOM % 900000 + 100000))
    local url_rand="${TARGET}${base}${rand_id}"

    # Ambil response ringan
    local r1=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url1" 2>/dev/null || echo "000|0")
    local r2=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url2" 2>/dev/null || echo "000|0")
    local rr=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" -k --max-time 10 "$url_rand" 2>/dev/null || echo "000|0")

    local code1=${r1%%|*}  size1=${r1#*|}
    local code2=${r2%%|*}  size2=${r2#*|}
    local code_r=${rr%%|*} size_r=${rr#*|}

    # Cek jika ID 1 & 2 berhasil dan konten berbeda
    if [[ "$code1" == "200" && "$code2" == "200" && ("$size1" != "$size2" || "$code1" != "$code_r") ]]; then
        local snippet1=$(curl -s -k "$url1" | head -c 300 | strings)
        local snippet2=$(curl -s -k "$url2" | head -c 300 | strings)
        
        echo -e "\033[1;31m[POTENSI IDOR TINGGI] ${base} → ID 1 vs ID 2 berbeda!\033[0m"
        echo "   Size: $size1 vs $size2 bytes"
        echo "   Snippet ID 1: ${snippet1:0:150}..."
        echo "   Snippet ID 2: ${snippet2:0:150}..."
        echo
    elif [[ "$code1" == "200" && "$code_r" == "200" ]]; then
        echo -e "\033[1;33m[POTENSI OPEN ACCESS] ID random $rand_id di ${base} berhasil (size: $size_r bytes)\033[0m"
    fi
done

echo -e "\033[1;32m[+] Scan selesai! Semua hasil di atas adalah nyata dari server target.\033[0m"
echo -e "\033[1;37m[+] Gunakan hanya pada target yang kamu punya izin resmi ya!\033[0m"
