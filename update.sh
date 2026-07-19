#!/bin/bash
# ============================================
# อัปเดตสคริปต์เมนูจาก GitHub
# EKROMVPN SSH - Auto Update
# ใช้งาน: curl -s https://raw.githubusercontent.com/ekromvpn/SSH/main/update | bash
# ============================================

clear
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[1;34m'; CYAN='\033[1;36m'; WHITE='\033[1;37m'; NC='\033[0m'
REPO="https://raw.githubusercontent.com/ekromvpn/SSH/main"

echo -e "${CYAN}============================================================${NC}"
echo -e "${BLUE}            ระบบอัปเดตสคริปต์ EKROMVPN SSH${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ตรวจสอบเวอร์ชันปัจจุบัน
CURRENT_VER="1.0"
if [ -f /usr/sbin/version ]; then
    CURRENT_VER=$(cat /usr/sbin/version)
fi

# ถ้าใช้ --force ให้ข้ามเช็คเวอร์ชัน อัปเดตเลย
FORCE_MODE=false
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    FORCE_MODE=true
fi

# ตรวจสอบเวอร์ชันล่าสุด
echo -e "${YELLOW}กำลังตรวจสอบเวอร์ชันล่าสุด...${NC}"
NEW_VER=$(curl -sS "${REPO}/version" 2>/dev/null || echo "1.0")

echo -e "${WHITE}เวอร์ชันปัจจุบัน: ${GREEN}$CURRENT_VER${NC}"
echo -e "${WHITE}เวอร์ชันล่าสุด  : ${GREEN}$NEW_VER${NC}"

if [ "$FORCE_MODE" = false ]; then
    if [ "$CURRENT_VER" = "$NEW_VER" ]; then
        echo ""
        echo -e "${GREEN}✅ สคริปต์เวอร์ชันล่าสุดแล้ว ไม่จำเป็นต้องอัปเดต${NC}"
        echo ""
        read -n 1 -s -r -p "กด Enter เพื่อกลับ..."
        [ -f /usr/sbin/menu ] && menu
        exit 0
    fi
else
    echo -e "${YELLOW}⚠️ โหมดบังคับอัปเดต กำลังดำเนินการ...${NC}"
fi

echo -e "${YELLOW}⚠️ พบเวอร์ชันใหม่! กำลังอัปเดต...${NC}"
sleep 1

# Backup เมนูเก่า
BACKUP_DIR="/root/menu-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /usr/sbin/menu "$BACKUP_DIR/" 2>/dev/null
echo -e "${GREEN}✓${NC} สำรองเมนูเก่าไปที่ $BACKUP_DIR"

# ดาวน์โหลดเมนูใหม่
echo -e "${YELLOW}กำลังดาวน์โหลดเมนูใหม่...${NC}"
cd /tmp
rm -f menu.zip
wget -q "${REPO}/config/menu.zip" -O menu.zip 2>/dev/null
if [ $? -ne 0 ] || [ ! -f menu.zip ]; then
    echo -e "${RED}❌ ดาวน์โหลดล้มเหลว! ตรวจสอบการเชื่อมต่อ${NC}"
    read -n 1 -s -r -p "กด Enter เพื่อกลับ..."
    [ -f /usr/sbin/menu ] && menu
    exit 1
fi

# แตกไฟล์
rm -rf /tmp/menu-new
mkdir /tmp/menu-new
if command -v 7z &>/dev/null; then
    7z x menu.zip -y -o/tmp/menu-new/ >/dev/null 2>&1
elif command -v unzip &>/dev/null; then
    unzip -q menu.zip -d /tmp/menu-new/ 2>/dev/null
else
    apt-get install -y unzip >/dev/null 2>&1
    unzip -q menu.zip -d /tmp/menu-new/ 2>/dev/null
fi

# อัปเดตไฟล์
echo -e "${YELLOW}กำลังอัปเดตไฟล์เมนู...${NC}"
cd /tmp/menu-new
count=0
for f in *; do
    if [ -f "$f" ]; then
        chmod +x "$f"
        cp "$f" "/usr/sbin/$f" 2>/dev/null
        echo -e "  ${GREEN}✓${NC} อัปเดต $f"
        ((count++))
    fi
done

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}          ✅ อัปเดต $count ไฟล์เสร็จสมบูรณ์!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "${WHITE}เวอร์ชัน: ${YELLOW}$CURRENT_VER${NC} → ${GREEN}$NEW_VER${NC}"
echo -e "${WHITE}สำรองเมนูเก่าที่: ${YELLOW}$BACKUP_DIR${NC}"
echo ""
read -n 1 -s -r -p "กด Enter เพื่อเริ่มเมนู..."
menu
