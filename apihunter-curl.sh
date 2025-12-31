#!/bin/bash

# API Hunter Pure Curl - One Command Full Scan
# Usage: ./apihunter-curl.sh https://target.com
# atau ./apihunter-curl.sh target.com

TARGET="$1"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url>"
    echo "Contoh: $0 https://example.com"
    exit 1
fi

[[ ! "$TARGET" =~ ^http ]] && TARGET="https://$TARGET"
TARGET="${TARGET%/}"

echo -e "\033[1;34m[+] Memulai API Hunter Pure Curl pada: $TARGET\033[0m"
echo "=================================================="

PATHS=(
    ""
    "/.env" "/config" "/backup" "/db" "/admin" "/login"
    "/api" "/api/v1" "/v1" "/v2" "/graphql"
    "/swagger" "/swagger-ui.html" "/swagger.json" "/openapi.json" "/docs"
    "/debug" "/health" "/metrics" "/status" "/info" "/phpinfo.php"
    "/.git/HEAD" "/.git/config" "/robots.txt" "/sitemap.xml"
    "/server-status" "/actuator" "/trace"
)

# Tambahan paths untuk potensi IDOR testing (endpoint dengan ID parameter)
IDOR_PATHS=(
    "/api/user/1" "/api/user/2"
    "/profile/1" "/profile/2"
    "/api/account/1" "/api/account/2"
    "/user/1" "/user/2"
    "/api/item/1" "/api/item/2"
)

for path in "${PATHS[@]}"; do
    url="$TARGET$path"
    response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{url_effective}" -k -m 10 "$url")
    code=$(echo $response | cut -d'|' -f1)
    size=$(echo $response | cut -d'|' -f2)
    final_url=$(echo $response | cut -d'|' -f3)

    # Hanya proses jika ada response
    if [[ "$code" == "000" ]]; then continue; fi

    # Highlight temuan menarik
    if [[ "$code" == "200" ]]; then
        if [[ "$path" == *".env"* || "$path" == *".git"* || "$path" == *"config"* || "$path" == *"backup"* ]]; then
            echo -e "\033[1;31m[CRITICAL] $code → $final_url (SIZE: $size bytes)\033[0m"
            curl -s -k "$url" | head -20
            echo
        elif [[ "$path" == *"/swagger"* || "$path" == *"/openapi"* || "$path" == *"/docs"* ]]; then
            echo -e "\033[1;33m[API DOCS] $code → $final_url\033[0m"
        elif [[ "$path" == *"/debug"* || "$path" == *"/admin"* || "$path" == *"/phpinfo"* ]]; then
            echo -e "\033[1;35m[POTENTIAL EXPOSED] $code → $final_url\033[0m"
        else
            content=$(curl -s -k "$url")
            if echo "$content" | grep -qiE "(api[_-]?key|token|secret|password|aws_access_key|bearer|sk_live_|pk_live_)" >/dev/null; then
                echo -e "\033[1;31m[LEAK DETECTED] $code → $final_url\033[0m"
                echo "$content" | grep -iE "(api[_-]?key|token|secret|password|aws_access_key|bearer|sk_live_|pk_live_)" | head -5
                echo
            fi
        fi

        # Deteksi token spesifik dengan regex lengkap
        if [[ "$code" == "200" ]]; then
            content=$(curl -s -k "$url")
            leaks=$(echo "$content" | grep -ioE 'sk_(live|test)_[0-9a-zA-Z]{24}|sq0(atp|csp|idp|cs|ic|pca|u|cs|ac|cp|cg|cs|idp)_[0-9a-zA-Z\-_]{22,}|ATATT[0-9a-zA-Z]{3,}|cloud_id:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|heroku [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|HEROKU_API_KEY=[0-9a-f]{8}-|ya29\.[0-9a-zA-Z\-_]{80,}|1//[0-9a-zA-Z\-_]{70,}|AKIA[0-9A-Z]{16}|[0-9a-zA-Z/+]{40}|https://[a-z0-9-]+\.firebaseio\.com|"apiKey":\s*"AIza[0-9a-zA-Z]{35}"|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*|(api[-_]?key|token|secret|auth|password|bearer)[\s:=]+["'']?[a-zA-Z0-9\-_]{20,}["'']?' | head -n 10)
            if [[ -n "$leaks" ]]; then
                echo -e "\033[1;31m[DETAILED LEAK DETECTED] $code → $final_url\033[0m"
                echo "$leaks"
                echo
            fi
        fi
    elif [[ "$code" == "401" || "$code" == "403" ]]; then
        echo -e "\033[1;36m[PROTECTED] $code → $final_url\033[0m"
    fi
done

# Deteksi potensi IDOR (Insecure Direct Object Reference)
echo -e "\033[1;34m[+] Memulai Deteksi Potensi IDOR\033[0m"
echo "=================================================="
for base_path in "${IDOR_PATHS[@]}" ; do
    # Ambil base tanpa ID terakhir
    base=$(dirname "$base_path")
    id1="${base_path##*/1}"  # Asumsi ID 1
    id2="${base_path##*/2}"  # Asumsi ID 2, bisa diganti dengan ID random

    url1="$TARGET$base/1"
    url2="$TARGET$base/2"
    url_random="$TARGET$base/$((RANDOM % 1000000 + 1000000))"  # ID random tinggi untuk cek non-existent

    # Curl ke ID 1
    code1=$(curl -s -o /dev/null -w "%{http_code}" -k -m 10 "$url1")
    content1=$(curl -s -k "$url1")

    # Curl ke ID 2
    code2=$(curl -s -o /dev/null -w "%{http_code}" -k -m 10 "$url2")
    content2=$(curl -s -k "$url2")

    # Curl ke ID random (untuk cek non-existent)
    code_random=$(curl -s -o /dev/null -w "%{http_code}" -k -m 10 "$url_random")
    content_random=$(curl -s -k "$url_random")

    if [[ "$code1" == "200" && "$code2" == "200" && "$code1" != "$code_random" && "$content1" != "$content2" ]]; then
        echo -e "\033[1;31m[POTENSI IDOR] Akses ke $url1 dan $url2 berhasil tanpa auth, konten berbeda. Cek manual!\033[0m"
        echo "Response ID 1 (snippet): ${content1:0:100}"
        echo "Response ID 2 (snippet): ${content2:0:100}"
        echo
    elif [[ "$code1" == "200" && "$code_random" == "200" ]]; then
        echo -e "\033[1;33m[POTENSI IDOR LEMAH] Akses ke ID random $url_random berhasil. Mungkin open access, cek manual.\033[0m"
        echo
    fi
done

echo -e "\033[1;32m[+] Scan selesai! Semua temuan di atas adalah hasil nyata dari curl.\033[0m"
