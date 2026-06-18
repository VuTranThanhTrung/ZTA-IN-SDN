import os
import joblib
import pandas as pd
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime
from threading import Lock

import switch

class ZTASecurityController(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(ZTASecurityController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        
        # Mapping tên nhãn của bộ CIC-IDS-2017 (chỉ giữ lại các lớp Layer 3/4)
        self.label_names = {
            0: 'BENIGN',
            1: 'Brute Force',
            2: 'DDoS',
            3: 'DoS',
            4: 'Port Scan'
        }

        # Điểm tin cậy động của các Host: mặc định ban đầu là 1.0 (an toàn)
        self.trust_scores = {
            '10.0.0.1': 1.0, # SV WEB 1
            '10.0.0.2': 1.0, # SV WEB 2
            '10.0.0.3': 1.0, # DNS 1
            '10.0.0.4': 1.0, # DNS 2
            '10.0.0.5': 1.0, # DB 1
            '10.0.0.6': 1.0, # DB 2
            '10.0.0.7': 1.0, # Benign Host
            '10.0.0.8': 1.0  # Attacker Host
        }

        # Bộ đệm lưu trữ dữ liệu thống kê lưu lượng trong RAM
        self.flow_stats_buffer = []
        self.stats_lock = Lock()

        # Lưu trữ số lượng gói tin của các flow ở chu kỳ trước để kiểm tra tính hoạt động
        self.last_flow_packets = {}

        # Lưu trữ tất cả flow_id xuất hiện trong chu kỳ hiện tại để tránh dọn dẹp nhầm khi reply bị chia thành nhiều phần
        self.current_cycle_flow_ids = set()

        self.monitor_thread = hub.spawn(self._monitor)
        
        # Nạp mô hình pre-trained
        self.model_path = 'rf_model_multiclass.pkl'
        self.model_loaded = False
        self.flow_model = None
        self.load_model()

    def load_model(self):
        """Tải mô hình Random Forest pre-trained offline."""
        if os.path.exists(self.model_path):
            try:
                self.flow_model = joblib.load(self.model_path)
                self.logger.info("[+] Đã nạp thành công mô hình pre-trained: %s", self.model_path)
                self.model_loaded = True
            except Exception as e:
                self.logger.error("[!] Lỗi khi nạp mô hình: %s", str(e))
        else:
            self.logger.warning("[!] KHÔNG tìm thấy mô hình pre-trained: %s", self.model_path)
            self.logger.warning("[!] Vui lòng thu thập dữ liệu và chạy train_multiclass_offline.py trước.")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Đăng ký Switch (Datapath ID): %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                # Cấu hình Meter ID = 1 với rate = 50 packets/second
                self.configure_meter(datapath, meter_id=1, rate=50)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Hủy đăng ký Switch (Datapath ID): %016x', datapath.id)
                del self.datapaths[datapath.id]

    def configure_meter(self, datapath, meter_id, rate):
        """Cấu hình OpenFlow Meter Table để bóp băng thông các flow bị hạn chế."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        bands = [parser.OFPMeterBandDrop(rate=rate, burst_size=10)]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_PKTPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)
        self.logger.info("[ZTA METER] Đã thiết lập Meter ID %d trên Switch %016x với rate = %d pps", meter_id, datapath.id, rate)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(1)
            self.flow_predict()
            hub.sleep(9)

    def _request_stats(self, datapath):
        self.logger.debug('Gửi Stats Request tới Switch %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        
        # Chỉ lấy các routing flows (priority == 1) để phân tích hành vi
        priority_1_flows = [flow for flow in body if flow.priority == 1]
        
        new_entries = []
        ofproto = ev.msg.datapath.ofproto

        for stat in priority_1_flows:
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match.get('ip_proto', 0)
            
            icmp_code = -1
            icmp_type = -1
            tp_src = 0
            tp_dst = 0

            if ip_proto == 1:
                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)
            elif ip_proto == 6:
                tp_src = stat.match.get('tcp_src', 0)
                tp_dst = stat.match.get('tcp_dst', 0)
            elif ip_proto == 17:
                tp_src = stat.match.get('udp_src', 0)
                tp_dst = stat.match.get('udp_dst', 0)

            flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"
            self.current_cycle_flow_ids.add(flow_id)

            # Kiểm tra xem flow này có phát sinh gói tin mới kể từ chu kỳ trước không
            current_packets = stat.packet_count
            last_packets = self.last_flow_packets.get(flow_id, -1)

            # Tính số gói tin mới phát sinh trong chu kỳ này
            delta_packets = current_packets - last_packets if last_packets != -1 else current_packets

            if last_packets != -1 and delta_packets <= 2:
                # Nếu số gói tin tăng lên quá ít (<= 2 gói), đây chỉ là các gói tin đóng kết nối (FIN/ACK)
                # hoặc gói tin trễ, không phải hoạt động tấn công thực tế. Ta bỏ qua.
                continue

            # Cập nhật số gói tin của flow ở chu kỳ này
            self.last_flow_packets[flow_id] = current_packets
          
            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
            except Exception:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec if stat.duration_nsec > 0 else 0
            except Exception:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
                
            new_entries.append({
                'timestamp': timestamp,
                'datapath_id': ev.msg.datapath.id,
                'flow_id': flow_id,
                'ip_src': ip_src,
                'tp_src': tp_src,
                'ip_dst': ip_dst,
                'tp_dst': tp_dst,
                'ip_proto': ip_proto,
                'icmp_code': icmp_code,
                'icmp_type': icmp_type,
                'flow_duration_sec': stat.duration_sec,
                'flow_duration_nsec': stat.duration_nsec,
                'idle_timeout': stat.idle_timeout,
                'hard_timeout': stat.hard_timeout,
                'flags': stat.flags,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'packet_count_per_second': packet_count_per_second,
                'packet_count_per_nsecond': packet_count_per_nsecond,
                'byte_count_per_second': byte_count_per_second,
                'byte_count_per_nsecond': byte_count_per_nsecond
            })

        # Ghi các thông số luồng vào bộ đệm RAM (Thread-safe)
        if new_entries:
            with self.stats_lock:
                self.flow_stats_buffer.extend(new_entries)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        
        # Chỉ áp dụng Meter bóp băng thông cho các flow định tuyến (priority=1) của host nghi ngờ
        if priority == 1 and 'ipv4_src' in match:
            src_ip = match['ipv4_src']
            server_whitelist = {'10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6'}
            if src_ip not in server_whitelist and self.trust_scores.get(src_ip, 1.0) < 0.85:
                # Chèn chỉ thị Meter ID 1 vào trước hành động đầu ra
                inst.append(parser.OFPInstructionMeter(meter_id=1))
                # self.logger.info("[ZTA METER] Gắn Meter ID 1 cho luồng mới của Host nghi ngờ: %s", src_ip)

        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            
        datapath.send_msg(mod)

    def apply_hard_isolation(self, attacker_ip):
        """Cô lập hoàn toàn Host tấn công (Microsegmentation) bằng luật DROP priority 100."""
        self.logger.error("[ZTA POLICY - HARD ISOLATION] Phát hiện Tấn công Nghiêm trọng! Cô lập Host: %s", attacker_ip)
        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            
            # Rule 1: Chặn tất cả traffic đi RA từ attacker_ip (Vĩnh viễn: idle=0, hard=0)
            match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            self.add_flow(dp, priority=100, match=match_out, actions=[], idle=0, hard=0)

            # Rule 2: Chặn tất cả traffic đi VÀO attacker_ip (Vĩnh viễn: idle=0, hard=0)
            match_in = parser.OFPMatch(eth_type=0x0800, ipv4_dst=attacker_ip)
            self.add_flow(dp, priority=100, match=match_in, actions=[], idle=0, hard=0)

    def apply_rate_limiting(self, attacker_ip):
        """Bóp băng thông Host nghi ngờ bằng cách xóa các flow cũ, buộc áp dụng Meter ID 1 ở PacketIn."""
        # self.logger.warning("[ZTA POLICY - RATE LIMITING] Phát hiện Tấn công Trung bình! Bóp băng thông Host: %s", attacker_ip)
        for dp in list(self.datapaths.values()):
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            
            # Xóa các flow rules hiện tại của attacker_ip để buộc cài đặt lại kèm chỉ thị Meter
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            dp.send_msg(mod)

    def remove_restrictions(self, attacker_ip):
        """Khôi phục quyền truy cập của Host: xóa các rule chặn/giới hạn băng thông (DROP và Meter rules)."""
        # self.logger.info("[ZTA POLICY - RESTORE] Khôi phục quyền truy cập cho Host: %s (Trust Score >= 0.85)", attacker_ip)
        for dp in list(self.datapaths.values()):
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            
            # Xóa các flow rules chiều đi (bao gồm cả DROP priority 100 và METER priority 90)
            match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            mod_out = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match_out
            )
            dp.send_msg(mod_out)

            # Xóa các flow rules chiều về
            match_in = parser.OFPMatch(eth_type=0x0800, ipv4_dst=attacker_ip)
            mod_in = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match_in
            )
            dp.send_msg(mod_in)

    def flow_predict(self):
        # Nạp lại mô hình nếu trước đó chưa nạp được
        if not self.model_loaded:
            self.load_model()
            if not self.model_loaded:
                return

        # Lấy dữ liệu từ bộ đệm RAM để xử lý in-memory
        with self.stats_lock:
            copied_stats = list(self.flow_stats_buffer)
            self.flow_stats_buffer.clear()

        try:
            if len(copied_stats) == 0:
                # Nếu không có flow hoạt động, khôi phục nhẹ điểm tin cậy cho toàn bộ các host đã đăng ký
                for ip in list(self.trust_scores.keys()):
                    self.trust_scores[ip] = min(1.0, self.trust_scores[ip] + 0.02)
                self.print_trust_scores_report(stats={}, total_flows=0)
                return

            predict_flow_dataset = pd.DataFrame(copied_stats)
            raw_dataset = predict_flow_dataset.copy()

            # Tiền xử lý dữ liệu dự đoán
            flow_counts = predict_flow_dataset.groupby('ip_src').size().to_dict()
            packet_rates = predict_flow_dataset.groupby('ip_src')['packet_count_per_second'].sum().to_dict()
            unique_ports = predict_flow_dataset.groupby('ip_src')['tp_dst'].nunique().to_dict()

            df_clean = predict_flow_dataset.copy()
            df_clean['flow_count_src'] = df_clean['ip_src'].map(flow_counts)
            df_clean['packet_rate_src'] = df_clean['ip_src'].map(packet_rates)
            df_clean['unique_dst_ports_src'] = df_clean['ip_src'].map(unique_ports)

            # Drop columns to match training feature set exactly
            cols_to_drop = ['timestamp', 'datapath_id', 'flow_id', 'ip_src', 'ip_dst', 'tp_src']
            df_features = df_clean.drop(columns=cols_to_drop, errors='ignore')

            # Đảm bảo các thuộc tính khớp chính xác thứ tự với mô hình huấn luyện
            df_features = df_features[self.flow_model.feature_names_in_]
            
            # Dự đoán nhãn và xác suất
            y_flow_pred = self.flow_model.predict(df_features)
            y_flow_pred_proba = self.flow_model.predict_proba(df_features)

            # Khởi tạo điểm tin cậy cho các IP mới xuất hiện
            active_ips = set(raw_dataset['ip_src'].unique())
            for ip in active_ips:
                if ip not in self.trust_scores:
                    self.trust_scores[ip] = 1.0

            # Tính toán hình phạt cho mỗi host hoạt động dựa trên các flow của nó
            host_penalties = {ip: [] for ip in active_ips}
            host_total_flows = {ip: 0 for ip in active_ips}
            host_attack_flows = {ip: 0 for ip in active_ips}
            stats = {name: 0 for name in self.label_names.values()}
            active_flows_summary = {}

            for idx, pred in enumerate(y_flow_pred):
                ip_src = raw_dataset.iloc[idx]['ip_src']
                ip_dst = raw_dataset.iloc[idx]['ip_dst']
                
                # Lấy xác suất dự đoán của nhãn đó
                prob = y_flow_pred_proba[idx][pred]

                # Ngưỡng độ tin cậy tối thiểu: Nếu là nhãn độc hại nhưng độ tin cậy < 40%, tự động coi là BENIGN (0)
                # Độ tin cậy của BENIGN lúc này được tính bằng xác suất không phải là cuộc tấn công (1.0 - prob)
                if pred > 0 and prob < 0.40:
                    pred = 0
                    prob = 1.0 - prob

                label_name = self.label_names.get(pred, 'UNKNOWN')
                stats[label_name] = stats.get(label_name, 0) + 1

                # Thống kê kết nối hoạt động
                flow_key = (ip_src, ip_dst, label_name)
                if flow_key not in active_flows_summary:
                    active_flows_summary[flow_key] = {'count': 0, 'probs': []}
                active_flows_summary[flow_key]['count'] += 1
                active_flows_summary[flow_key]['probs'].append(prob)

                # Tính toán mức trừ điểm tin cậy (penalty) dựa trên độ nguy hiểm của nhãn (Layer 3/4)
                if pred in [2, 3]:          # High Severity (DDoS = 2, DoS = 3)
                    penalty = 0.3 * prob
                elif pred in [1, 4]:        # Medium Severity (Brute Force = 1, Port Scan = 4)
                    penalty = 0.15 * prob
                else:                       # Benign (0)
                    penalty = -0.05         # Thưởng (hành vi sạch)
                
                host_total_flows[ip_src] += 1
                if pred > 0:
                    host_attack_flows[ip_src] += 1

                host_penalties[ip_src].append(penalty)

                # Ghi nhận log gỡ lỗi đối với các flow không lành mạnh
                if pred > 0:
                    debug_file = "debug_detections.csv"
                    debug_exists = os.path.exists(debug_file)
                    with open(debug_file, "a+") as df_out:
                        if not debug_exists or os.path.getsize(debug_file) == 0:
                            df_out.write("predicted_label,ip_src,ip_dst," + ",".join(df_features.columns) + "\n")
                        row_vals = [str(pred), str(ip_src), str(ip_dst)] + [str(val) for val in df_features.iloc[idx].values]
                        df_out.write(",".join(row_vals) + "\n")

            # Cập nhật điểm tin cậy động cho các IP nguồn hoạt động
            for ip in active_ips:
                total_f = host_total_flows[ip]
                attack_f = host_attack_flows[ip]
                ratio = attack_f / total_f if total_f > 0 else 0.0
                
                # Chỉ áp dụng mức phạt nếu có ít nhất 5 luồng tấn công VÀ tỷ lệ luồng tấn công >= 20%
                if attack_f >= 5 and ratio >= 0.20:
                    max_penalty = max(host_penalties[ip])
                else:
                    # Nếu không thỏa mãn, không phạt (hưởng hồi phục nhẹ hoặc không trừ điểm)
                    max_penalty = -0.05
                
                self.trust_scores[ip] = max(0.0, min(1.0, self.trust_scores[ip] - max_penalty))

            # Khôi phục nhẹ điểm tin cậy (+0.02) cho tất cả các host đăng ký định kỳ mỗi 10 giây
            for ip in list(self.trust_scores.keys()):
                self.trust_scores[ip] = min(1.0, self.trust_scores[ip] + 0.02)

            # In báo cáo phân loại ZTA ra màn hình console kèm thời gian
            total_flows = len(y_flow_pred)
            self.print_trust_scores_report(stats, total_flows, active_flows_summary)

            # Áp dụng chính sách bảo mật dựa trên điểm tin cậy mới
            server_whitelist = {'10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6'}

            for ip, score in list(self.trust_scores.items()):
                # Chỉ áp dụng các luật trên các host nội bộ cục bộ
                if not str(ip).startswith("10.0.0."):
                    continue

                if ip in server_whitelist:
                    continue

                if score < 0.4:
                    # Cô lập cứng
                    self.apply_hard_isolation(ip)
                elif score < 0.85:
                    # Bóp băng thông
                    self.apply_rate_limiting(ip)
                else:
                    # Khôi phục hoàn toàn
                    self.remove_restrictions(ip)

        except Exception as e:
            self.logger.error("Lỗi trong quá trình dự đoán lưu lượng ZTA: %s", str(e))
        finally:
            # Chỉ dọn dẹp các flow đã hết hạn (không còn xuất hiện trên bất kỳ switch nào) vào cuối chu kỳ
            for fid in list(self.last_flow_packets.keys()):
                if fid not in self.current_cycle_flow_ids:
                    del self.last_flow_packets[fid]
            # Reset danh sách theo dõi cho chu kỳ tiếp theo
            self.current_cycle_flow_ids.clear()

    def print_trust_scores_report(self, stats, total_flows, active_flows_summary=None):
        role_annotations = {
            '10.0.0.1': ' (SV WEB 1)',
            '10.0.0.2': ' (SV WEB 2)',
            '10.0.0.3': ' (DNS 1)',
            '10.0.0.4': ' (DNS 2)',
            '10.0.0.5': ' (DB 1)',
            '10.0.0.6': ' (DB 2)',
            '10.0.0.7': '',
            '10.0.0.8': ''
        }
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Xác định màu sắc chủ đạo dựa trên trạng thái an toàn (Có tấn công: Màu đỏ, An toàn: Màu xanh)
        has_attack = any(stats.get(name, 0) > 0 for name in stats if name != 'BENIGN')
        color = "\033[91m" if has_attack else "\033[92m"  # Đỏ sáng nếu có tấn công, Xanh lá sáng nếu an toàn
        reset = "\033[0m"

        self.logger.info("%s=====================================================================%s", color, reset)
        self.logger.info("%s   BÁO CÁO GIÁM SÁT AN NINH MẠNG ZERO TRUST (ZTA) [%s]%s", color, now_str, reset)
        self.logger.info("%s=====================================================================%s", color, reset)
        self.logger.info("Tổng số flows đã quét: %d", total_flows)
        for name, count in stats.items():
            if count > 0:
                self.logger.info("  - %-15s: %d flows (chiếm %.2f%% tổng lưu lượng quét)", name, count, (count / total_flows) * 100)
        
        if active_flows_summary:
            self.logger.info("---------------------------------------------------------------------")
            self.logger.info("DANH SÁCH LUỒNG KẾT NỐI CHI TIẾT (ACTIVE FLOWS):")
            for (ip_src, ip_dst, label_name), info in sorted(active_flows_summary.items()):
                count = info['count']
                avg_prob = sum(info['probs']) / len(info['probs']) if info['probs'] else 0.0
                self.logger.info("  - [%s] -> [%s] | Nhãn: %s (%d flows) | Độ tin cậy của AI: %.1f%%",
                                 ip_src, ip_dst, label_name, count, avg_prob * 100)
        
        self.logger.info("---------------------------------------------------------------------")
        self.logger.info("BẢNG ĐIỂM TIN CẬY ĐỘNG (DYNAMIC TRUST SCORE):")
        for ip, score in sorted(self.trust_scores.items()):
            role = role_annotations.get(ip, '')
            if score < 0.4:
                status = "\033[91mCÁCH LY CỨNG\033[0m"       # Đỏ sáng
            elif score < 0.85:
                status = "\033[93mGIỚI HẠN BĂNG THÔNG\033[0m" # Vàng sáng
            else:
                status = "\033[92mAN TOÀN\033[0m"             # Xanh lá sáng
            self.logger.info("  - Host %-15s%s: Trust Score = %.2f [%s]", ip, role, score, status)
        self.logger.info("%s=====================================================================%s", color, reset)
