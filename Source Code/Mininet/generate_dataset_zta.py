#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: generate_dataset_zta.py
Mục đích: Tự động hóa sinh lưu lượng mạng (Traffic Generation) trong môi trường Mininet
sử dụng chính xác các công cụ và câu lệnh mô tả trong tài liệu "cac_cau_lenh_sinh_traffic.md".
Bộ dữ liệu gồm 5 lớp (Classes) được lưu trực tiếp thành các file CSV riêng biệt:
  0. Benign (Lưu lượng sạch - wget, curl, ab, iperf3, dig, nslookup, ping từ nhiều host)
  1. Brute Force (Tấn công dò quét thông tin đăng nhập bằng ncrack trên cổng 22 SSH và cổng 21 FTP)
  2. DDoS (Tấn công SYN/UDP/ICMP Flood giả mạo IP nguồn --rand-source với chế độ --flood)
  3. DoS (Tấn công đơn nguồn Slowloris, Slow POST bằng slowhttptest và TCP SYN Flood --flood)
  4. Port Scan (Quét cổng TCP SYN Scan -sS, TCP Connect -sT, UDP Scan -sU bằng nmap)
"""

import os
import sys
import time
from datetime import datetime
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.node import OVSKernelSwitch, RemoteController

# File cấu hình để Ryu Controller nhận diện file đầu ra và nhãn tương ứng
FILENAME_FILE = "/home/vuxtrung/KLTN_ver2/Source Code/Controller/current_filename.txt"
LABEL_FILE = "/home/vuxtrung/KLTN_ver2/Source Code/Controller/current_label.txt"

def set_controller_config(filename, label):
    """Ghi cấu hình file CSV và nhãn hiện tại để Ryu Controller lưu dữ liệu."""
    print(f"\n[CẤU HÌNH CONTROLLER] >>> Ghi vào file: {filename} | Nhãn: {label} <<<")
    with open(FILENAME_FILE, "w") as f:
        f.write(filename)
    with open(LABEL_FILE, "w") as f:
        f.write(str(label))

def clear_switch_flows():
    """Xóa sạch bảng Flow Table trên các Switch ảo để tránh dữ liệu trùng lặp giữa các pha."""
    print("[HỆ THỐNG] Đang xóa sạch các flow cũ trên các Switch ảo OVS...")
    for sw in ['s1', 's2', 's3', 's4']:
        os.system(f"sudo ovs-ofctl -O OpenFlow13 del-flows {sw} 2>/dev/null")
    time.sleep(1)

class ZTATopo(Topo):
    """
    Thiết lập mạng 4 Switch tương ứng với 4 Zone:
      s1: Web Zone (h1: 10.0.0.1, h2: 10.0.0.2)
      s2: DNS Zone (h3: 10.0.0.3, h4: 10.0.0.4)
      s3: DB Zone  (h5: 10.0.0.5, h6: 10.0.0.6)
      s4: Host Zone (h7: 10.0.0.7, h8: 10.0.0.8)
    """
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24")
        h5 = self.addHost('h5', cpu=1.0/20, mac="00:00:00:00:00:05", ip="10.0.0.5/24")
        h6 = self.addHost('h6', cpu=1.0/20, mac="00:00:00:00:00:06", ip="10.0.0.6/24")
        h7 = self.addHost('h7', cpu=1.0/20, mac="00:00:00:00:00:07", ip="10.0.0.7/24")
        h8 = self.addHost('h8', cpu=1.0/20, mac="00:00:00:00:00:08", ip="10.0.0.8/24")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h7, s4)
        self.addLink(h8, s4)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)

def startNetwork():
    topo = ZTATopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    print("[*] Đang khởi động mạng ảo Mininet...")
    net.start()

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h5 = net.get('h5')
    h6 = net.get('h6')
    h7 = net.get('h7')
    h8 = net.get('h8')

    print("[*] Khởi chạy các dịch vụ Web Server, iperf3 server...")
    # Khởi động dịch vụ HTTP Web Server trên h1 và h2
    h1.cmd('python3 -m http.server 80 &')
    h2.cmd('python3 -m http.server 80 &')
    
    # Khởi động iperf3 server dạng daemon trên h1 phục vụ đo băng thông
    h1.cmd('iperf3 -s -D')
    time.sleep(2)

    # ═══════════════════════════════════════════════════════════════
    # GIAI ĐOẠN 0: BENIGN TRAFFIC (LƯU LƯỢNG SẠCH - NHÃN 0)
    # ═══════════════════════════════════════════════════════════════
    set_controller_config("benign.csv", 0)
    print("\n[+] GIAI ĐOẠN 0: BẮT ĐẦU TẠO LƯU LƯỢNG SẠCH (BENIGN)")
    print("Giải thích cmd sinh traffic sạch (Theo cac_cau_lenh_sinh_traffic.md):")
    print("  -> h3: ab -n 500 -c 10 http://10.0.0.1/ (Apache Benchmark gửi 500 request, 10 đồng thời)")
    print("  -> h4: iperf3 -c 10.0.0.1 -t 5 (Truyền tải TCP sạch 5 giây)")
    print("  -> h4: iperf3 -c 10.0.0.1 -u -b 5M -t 5 (Truyền tải UDP sạch 5M băng thông trong 5 giây)")
    print("  -> h5: dig @10.0.0.3 www.google.com (Truy vấn DNS bằng dig)")
    print("  -> h5: nslookup www.baidu.com 10.0.0.4 (Truy vấn DNS bằng nslookup)")
    print("  -> h6: wget -qO- http://10.0.0.1/ (Tải trang bằng wget)")
    print("  -> h6: curl -s http://10.0.0.2/ (Tải trang bằng curl)")
    print("  -> h7: ping -c 5 10.0.0.5 (Kiểm tra ping sạch tới DB Server)")

    for round_idx in range(10):
        print(f"  -> Đợt {round_idx+1}/10: Gửi lưu lượng sạch từ nhiều host...")
        # Host h3 chạy Apache Benchmark (ab)
        h3.cmd("ab -n 500 -c 10 http://10.0.0.1/ >/dev/null 2>&1 &")
        
        # Host h4 đo băng thông bằng iperf3 (TCP & UDP)
        h4.cmd("iperf3 -c 10.0.0.1 -t 5 >/dev/null 2>&1 &")
        h4.cmd("iperf3 -c 10.0.0.1 -u -b 5M -t 5 >/dev/null 2>&1 &")
        
        # Host h5 truy vấn DNS
        h5.cmd("dig @10.0.0.3 www.google.com >/dev/null 2>&1 &")
        h5.cmd("nslookup www.baidu.com 10.0.0.4 >/dev/null 2>&1 &")
        
        # Host h6 thực hiện curl/wget
        h6.cmd("wget -qO- http://10.0.0.1/ >/dev/null 2>&1 &")
        h6.cmd("curl -s http://10.0.0.2/ >/dev/null 2>&1 &")
        
        # Host h7 thực hiện ping sạch
        h7.cmd("ping -c 5 10.0.0.5 >/dev/null 2>&1 &")
        
        time.sleep(8)
        clear_switch_flows()

    # ═══════════════════════════════════════════════════════════════
    # GIAI ĐOẠN 1: BRUTE FORCE ATTACK (NHÃN 1)
    # ═══════════════════════════════════════════════════════════════
    set_controller_config("bruteforce.csv", 1)
    print("\n[+] GIAI ĐOẠN 1: BẮT ĐẦU TẠO TẤN CÔNG BRUTE FORCE (NCRACK)")
    print("Giải thích cmd sinh traffic Brute Force (Theo cac_cau_lenh_sinh_traffic.md):")
    print("  -> h8: ncrack -p 22 --user admin --pass admin 10.0.0.1 (Dò quét cổng SSH 22)")
    print("  -> h7: ncrack -p 21 --user admin --pass admin 10.0.0.2 (Dò quét cổng FTP 21)")

    print("  -> Tiến hành: h8 và h7 khởi chạy Ncrack quét thông tin đăng nhập...")
    h8.cmd("ncrack -p 22 --user admin --pass admin 10.0.0.1 >/dev/null 2>&1 &")
    h7.cmd("ncrack -p 21 --user admin --pass admin 10.0.0.2 >/dev/null 2>&1 &")
    time.sleep(12)
    os.system("sudo pkill -9 ncrack")
    clear_switch_flows()

    # ═══════════════════════════════════════════════════════════════
    # GIAI ĐOẠN 2: DDOS ATTACK (NHÃN 2)
    # ═══════════════════════════════════════════════════════════════
    set_controller_config("ddos.csv", 2)
    print("\n[+] GIAI ĐOẠN 2: BẮT ĐẦU TẠO TẤN CÔNG DDOS (--FLOOD & --RAND-SOURCE)")
    print("Giải thích cmd sinh traffic DDoS (Theo cac_cau_lenh_sinh_traffic.md):")
    print("  -> h8: hping3 -S -p 80 --flood --rand-source 10.0.0.1 (DDoS TCP SYN Flood)")
    print("  -> h7: hping3 --udp -p 53 --flood --rand-source 10.0.0.3 (DDoS UDP Flood)")
    print("  -> h6: hping3 -1 --flood --rand-source 10.0.0.1 (DDoS ICMP Flood)")
    print("  -> *Lưu ý: Chế độ --flood gửi gói tin nhanh nhất có thể và chạy ngầm. Sau đó sẽ bị pkill để dừng lại.")

    for round_idx in range(3):
        print(f"  -> Đợt {round_idx+1}/3: h8, h7 và h6 đồng thời gửi ngập lụt DDoS giả mạo IP nguồn...")
        h8.cmd("hping3 -S -p 80 --flood --rand-source 10.0.0.1 >/dev/null 2>&1 &")
        h7.cmd("hping3 --udp -p 53 --flood --rand-source 10.0.0.3 >/dev/null 2>&1 &")
        h6.cmd("hping3 -1 --flood --rand-source 10.0.0.1 >/dev/null 2>&1 &")
        time.sleep(10)
        os.system("sudo pkill -9 hping3")
        clear_switch_flows()

    # ═══════════════════════════════════════════════════════════════
    # GIAI ĐOẠN 3: DOS ATTACK (NHÃN 3)
    # ═══════════════════════════════════════════════════════════════
    set_controller_config("dos.csv", 3)
    print("\n[+] GIAI ĐOẠN 3: BẮT ĐẦU TẠO TẤN CÔNG DOS (SLOWHTTPTEST & HPING3 ĐƠN NGUỒN)")
    print("Giải thích cmd sinh traffic DoS (Theo cac_cau_lenh_sinh_traffic.md):")
    print("  -> h8: slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://10.0.0.1/ (Slowloris GET)")
    print("  -> h7: slowhttptest -c 1000 -B -i 10 -r 200 -s 8192 -t POST -u http://10.0.0.2/ (Slow POST)")
    print("  -> h5: hping3 -S -p 80 --flood 10.0.0.1 (TCP SYN Flood DoS không giả mạo IP)")

    for round_idx in range(3):
        print(f"  -> Đợt {round_idx+1}/3: h8, h7 và h5 đồng thời tấn công DoS cường độ cao...")
        h8.cmd("slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://10.0.0.1/ >/dev/null 2>&1 &")
        h7.cmd("slowhttptest -c 1000 -B -i 10 -r 200 -s 8192 -t POST -u http://10.0.0.2/ >/dev/null 2>&1 &")
        h5.cmd("hping3 -S -p 80 --flood 10.0.0.1 >/dev/null 2>&1 &")
        time.sleep(10)
        os.system("sudo pkill -9 slowhttptest")
        os.system("sudo pkill -9 hping3")
        clear_switch_flows()

    # ═══════════════════════════════════════════════════════════════
    # GIAI ĐOẠN 4: PORT SCANNING (NHÃN 4)
    # ═══════════════════════════════════════════════════════════════
    set_controller_config("portscan.csv", 4)
    print("\n[+] GIAI ĐOẠN 4: BẮT ĐẦU TẠO HOẠT ĐỘNG DÒ QUÉT CỔNG (NMAP)")
    print("Giải thích cmd quét cổng (Theo cac_cau_lenh_sinh_traffic.md):")
    print("  -> h8: nmap -sS -p 1-65535 10.0.0.1 (TCP SYN Stealth Scan quét toàn bộ cổng)")
    print("  -> h7: nmap -sT -p 1-1000 10.0.0.2 (TCP Connect Scan)")
    print("  -> h6: nmap -sU -p 1-100 10.0.0.1 (UDP Scan)")

    print("  -> Tiến hành: h8, h7 và h6 đồng thời chạy Nmap dò quét các host...")
    h8.cmd("nmap -sS -p 1-65535 10.0.0.1 >/dev/null 2>&1 &")
    h7.cmd("nmap -sT -p 1-1000 10.0.0.2 >/dev/null 2>&1 &")
    h6.cmd("nmap -sU -p 1-100 10.0.0.1 >/dev/null 2>&1 &")
    time.sleep(12)
    os.system("sudo pkill -9 nmap")
    clear_switch_flows()

    print("\n[HỆ THỐNG] Quá trình sinh dữ liệu hoàn tất! Đang dọn dẹp các dịch vụ nền...")
    os.system("sudo pkill -f iperf3")
    os.system("sudo pkill -f http.server")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    print("[HỆ THỐNG] Đang dọn dẹp các bridge ảo cũ trên OVS...")
    for i in range(1, 5):
        os.system(f'sudo ovs-vsctl del-br s{i} >/dev/null 2>&1')
    
    start_time = datetime.now()
    startNetwork()
    end_time = datetime.now()
    print(f"\n[+] Tổng thời gian chạy giả lập thu thập dữ liệu: {end_time - start_time}")
