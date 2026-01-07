#!/bin/bash

# Warna untuk output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== API IDOR Scanner (Real-time) ===${NC}"

# Input dari user
read -p "Masukkan Base URL (Contoh: https://api.target.com/v1/users/FUZZ): " URL
read -p "Masukkan Range Awal ID: " START
read -p "Masukkan Range Akhir ID: " END
read -p "Masukkan Cookie/Header (Opsional, kosongkan jika tidak ada): " COOKIE

echo -e "\n${YELLOW}Memulai scanning dari ID $START sampai $END...${NC}\n"
echo "------------------------------------------------"

for ((id=$START; id<=$END; id++))
do
    # Mengganti keyword FUZZ dengan ID saat ini
    TARGET_URL=$(echo $URL | sed "s/FUZZ/$id/g")

    # Eksekusi CURL
    # -s: Silent
    # -o /dev/null: Buang body respon
    # -w: Ambil HTTP code dan panjang respon (Size)
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
        -H "Cookie: $COOKIE" \
        -H "Content-Type: application/json" \
        "$TARGET_URL")

    HTTP_CODE=$(echo $RESPONSE | cut -d':' -f1)
    SIZE=$(echo $RESPONSE | cut -d':' -f2)

    # Logika filter hasil
    if [ "$HTTP_CODE" == "200" ]; then
        echo -e "${GREEN}[+] 200 OK | ID: $id | Size: $SIZE | URL: $TARGET_URL${NC}"
        # Simpan hasil temuan ke file
        echo "[+] ID: $id | Size: $SIZE | URL: $TARGET_URL" >> valid_idor_results.txt
    elif [ "$HTTP_CODE" == "403" ] || [ "$HTTP_CODE" == "401" ]; then
        echo -e "${RED}[-] $HTTP_CODE Forbidden/Unauthorized | ID: $id${NC}"
    else
        echo -e "${NC}[.] $HTTP_CODE | ID: $id${NC}"
    fi
done

echo -e "\n${YELLOW}Scanning selesai. Hasil disimpan di valid_idor_results.txt${NC}"
