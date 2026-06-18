#!/bin/bash
# Source Code/Mininet/microsegment.sh
# Kịch bản Zero-Trust Host Microsegmentation cho Topo 4 Switch (h1-h8)
# ═══════════════════════════════════════════════════════════════════════

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   TRIỂN KHAI ZERO TRUST IPv4 MICRO-SEGMENTATION (h1-h8)     ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Bước 1: Xóa luật cũ trên toàn bộ host
echo "[1/4] Đang dọn dẹp các luật iptables cũ trên các host..."
for host in h1 h2 h3 h4 h5 h6 h7 h8; do
    ip netns exec $host iptables -F INPUT 2>/dev/null
    ip netns exec $host iptables -F FORWARD 2>/dev/null
    ip netns exec $host iptables -F OUTPUT 2>/dev/null
    ip netns exec $host iptables -P INPUT ACCEPT
    ip netns exec $host iptables -P OUTPUT ACCEPT
done
echo "     ✓ Đã xóa sạch!"

# Bước 2: Thiết lập Web Tier (h1, h2)
echo "[2/4] Thiết lập phân đoạn cho Web Tier (h1, h2)..."
# Chặn lây lan ngang giữa web1 và web2
ip netns exec h1 iptables -A INPUT -s 10.0.0.2 -j DROP
ip netns exec h2 iptables -A INPUT -s 10.0.0.1 -j DROP

for web in h1 h2; do
    ip netns exec $web iptables -A INPUT -i lo -j ACCEPT
    ip netns exec $web iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Cho phép HTTP/S (port 80, 443) đi vào từ mọi host
    ip netns exec $web iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
    # Chặn mọi truy cập không hợp lệ khác đi vào Web
    ip netns exec $web iptables -A INPUT -j DROP
done

# Bước 3: Thiết lập DNS Tier (h3, h4)
echo "[3/4] Thiết lập phân đoạn cho DNS Tier (h3, h4)..."
for dns in h3 h4; do
    ip netns exec $dns iptables -A INPUT -i lo -j ACCEPT
    ip netns exec $dns iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Cho phép truy vấn DNS (UDP/TCP port 53)
    ip netns exec $dns iptables -A INPUT -p udp --dport 53 -j ACCEPT
    ip netns exec $dns iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    # Chặn mọi truy cập khác đi vào DNS
    ip netns exec $dns iptables -A INPUT -j DROP
done

# Bước 4: Thiết lập Database Tier (h5, h6)
echo "[4/4] Thiết lập phân đoạn cho Database Tier (h5, h6)..."
# Cho phép replication/cluster giữa db1 và db2
ip netns exec h5 iptables -A INPUT -s 10.0.0.6 -j ACCEPT
ip netns exec h6 iptables -A INPUT -s 10.0.0.5 -j ACCEPT

for db in h5 h6; do
    ip netns exec $db iptables -A INPUT -i lo -j ACCEPT
    ip netns exec $db iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Chỉ cho phép Web Tier (h1, h2) kết nối tới CSDL MySQL (port 3306)
    ip netns exec $db iptables -A INPUT -s 10.0.0.1 -p tcp --dport 3306 -j ACCEPT
    ip netns exec $db iptables -A INPUT -s 10.0.0.2 -p tcp --dport 3306 -j ACCEPT
    # Chặn mọi truy cập khác đi vào DB
    ip netns exec $db iptables -A INPUT -j DROP
done
# Bước 5: In báo cáo chính sách bảo mật đã áp dụng
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              BÁO CÁO CHÍNH SÁCH ĐÃ ÁP DỤNG                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║ QT1: h1 <-> h2               │ ✗ DENY  (Cách ly ngang Web)  ║"
echo "║ QT2: * -> h1/h2 (80, 443)    │ ✓ ALLOW (Dịch vụ HTTP/S)     ║"
echo "║ QT3: * -> h1/h2 (Còn lại)    │ ✗ DENY  (Bảo vệ Web Server)  ║"
echo "║ QT4: h5 <-> h6               │ ✓ ALLOW (Đồng bộ CSDL)       ║"
echo "║ QT5: h1/h2 -> h5/h6 (TCP3306)│ ✓ ALLOW (Truy vấn CSDL)      ║"
echo "║ QT6: * -> h5/h6 (Còn lại)    │ ✗ DENY  (Bảo vệ lõi CSDL)    ║"
echo "║ QT7: * -> h3/h4 (Port 53)    │ ✓ ALLOW (Phân giải tên DNS)  ║"
echo "║ QT8: * -> h3/h4 (Còn lại)    │ ✗ DENY  (Bảo vệ DNS Server)  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Hoàn thành! Zero-Trust Microsegmentation đã được áp dụng thành công."
