#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController

class ZTACLI(CLI):
    def _setup_netns(self):
        """Tạo symlink netns để 'ip netns exec' hoạt động với Mininet nodes."""
        os.system("mkdir -p /var/run/netns")
        for name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8']:
            if name in self.mn:
                node = self.mn[name]
                os.system(f"ln -sf /proc/{node.pid}/ns/net /var/run/netns/{name}")

    def do_acl(self, line):
        """Kích hoạt Zero Trust Host-level Micro-segmentation qua iptables."""
        self._setup_netns()
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'microsegment.sh')
        if os.path.exists(script):
            os.system(f'chmod +x "{script}" && bash "{script}"')
        else:
            print(f"[!] Không tìm thấy script {script}")

    def do_dropacl(self, line):
        """Gỡ bỏ toàn bộ quy tắc Zero Trust Firewall trên các host."""
        self._setup_netns()
        for name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8']:
            os.system(f"ip netns exec {name} iptables -F INPUT 2>/dev/null")
            os.system(f"ip netns exec {name} iptables -F FORWARD 2>/dev/null")
            os.system(f"ip netns exec {name} iptables -F OUTPUT 2>/dev/null")
            os.system(f"ip netns exec {name} iptables -P INPUT ACCEPT 2>/dev/null")
        print("[+] Đã gỡ bỏ toàn bộ rào chắn Firewall trên các host!")

class ZTATopo(Topo):
    def build(self):
        # 4 Switches đại diện cho các zone
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13') # Web Zone
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13') # DNS Zone
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13') # DB Zone
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13') # User/Attacker Zone

        # Hosts trong Web Zone (sw1)
        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24") # Web Server 1
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24") # Web Server 2

        # Hosts trong DNS Zone (sw2)
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24") # DNS Server 1
        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24") # DNS Server 2

        # Hosts trong DB Zone (sw3)
        h5 = self.addHost('h5', cpu=1.0/20, mac="00:00:00:00:00:05", ip="10.0.0.5/24") # DB Server 1
        h6 = self.addHost('h6', cpu=1.0/20, mac="00:00:00:00:00:06", ip="10.0.0.6/24") # DB Server 2

        # Hosts trong User/Attacker Zone (sw4)
        h7 = self.addHost('h7', cpu=1.0/20, mac="00:00:00:00:00:07", ip="10.0.0.7/24") # Benign Host
        h8 = self.addHost('h8', cpu=1.0/20, mac="00:00:00:00:00:08", ip="10.0.0.8/24") # Attacker Host

        # Add links từ hosts đến switch tương ứng
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h7, s4)
        self.addLink(h8, s4)

        # Kết nối các switch thành đường thẳng s1 - s2 - s3 - s4
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)

def startNetwork():
    topo = ZTATopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    print("[*] Đang khởi động mạng Mininet...")
    net.start()
    
    print("\n=== TOPOLOGY ĐÃ ĐƯỢC THIẾT LẬP ===")
    print("  s1 (Web Zone) <-> h1 (10.0.0.1), h2 (10.0.0.2)")
    print("  s2 (DNS Zone) <-> h3 (10.0.0.3), h4 (10.0.0.4)")
    print("  s3 (DB Zone)  <-> h5 (10.0.0.5), h6 (10.0.0.6)")
    print("  s4 (Host Zone)<-> h7, h8 ")
    print("===================================\n")
    print("[*] Sử dụng lệnh 'acl' để bật Zero-Trust Microsegmentation.")
    print("[*] Sử dụng lệnh 'dropacl' để tắt rào chắn Firewall.\n")

    ZTACLI(net)
    
    print("[*] Đang dừng mạng Mininet...")
    net.stop()

def mn_cleanup():
    print("[*] Đang dọn dẹp các switch ảo OVS cũ (tránh kill Controller)...")
    for i in range(1, 5):
        os.system(f'sudo ovs-vsctl del-br s{i} >/dev/null 2>&1')

if __name__ == '__main__':
    setLogLevel('info')
    mn_cleanup()
    startNetwork()
