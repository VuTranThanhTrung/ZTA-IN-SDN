import os
import sys
import pandas as pd
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime
from threading import Lock

# Controller điều phối pipeline ZTA-SDN: thu thập flow, dự đoán ML,
# cập nhật trust score và thực thi chính sách bằng OpenFlow.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../Emulation')))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import switch
from ml_engine import DEFAULT_MODEL_FILENAME, MLDetectionEngine
from policy_engine import DynamicPolicyEngine
from mitigation_strategies import MitigationExecutor
from identity_provider import MockAAAServer, IdentityContextAnalyzer


class ZTASecurityController(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(ZTASecurityController, self).__init__(*args, **kwargs)

        # Lưu các switch đang kết nối theo Datapath ID.
        self.datapaths = {}

        # Buffer gom thống kê flow giữa luồng nhận reply và luồng dự đoán định kỳ.
        self.flow_stats_buffer = []
        self.stats_lock = Lock()

        # Theo dõi packet counter để bỏ qua flow ít thay đổi và dọn flow đã hết hạn.
        self.last_flow_packets = {}
        self.current_cycle_flow_ids = set()

        self.label_names = {
            0: 'BENIGN',
            1: 'DDoS',
            2: 'DoS',
            3: 'Port Scan'
        }
        # Penalty = severity_weight(label) * combined_risk.
        self.attack_severity_weights = {
            0: 0.00,  # BENIGN
            1: 0.30,  # DDoS
            2: 0.30,  # DoS
            3: 0.15   # Port Scan
        }

        # Dùng đường dẫn tuyệt đối để controller chạy ổn định từ mọi thư mục làm việc.
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_dir = os.path.abspath(os.path.join(base_dir, '../Model'))
        model_path = os.path.join(model_dir, DEFAULT_MODEL_FILENAME)
        aaa_config = os.path.abspath(os.path.join(base_dir, '../Emulation/aaa_users.json'))

        # Các thành phần chính của pipeline ZTA.
        self.ml_engine = MLDetectionEngine(model_path, self.logger)
        self.aaa_server = MockAAAServer(aaa_config, self.logger)
        self.identity_analyzer = IdentityContextAnalyzer(self.aaa_server, self.logger)
        self.policy_engine = DynamicPolicyEngine(self.logger)
        self.mitigation_executor = MitigationExecutor(self.datapaths, self.logger)

        # Khởi tạo trust score cho các host trong topology Mininet.
        default_hosts = [
            '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4',
            '10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.0.8'
        ]
        for host in default_hosts:
            self.policy_engine.update_trust_score(host, 0.0)

        # Green thread giám sát định kỳ, không chặn vòng lặp sự kiện OpenFlow.
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Đăng ký Switch (Datapath ID): %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                # Meter ID 1 dùng cho rate limiting trong vùng microsegment.
                self.mitigation_executor.configure_meter(datapath, meter_id=1, rate=50)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Hủy đăng ký Switch (Datapath ID): %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        # Mỗi chu kỳ khoảng 10 giây: request stats -> chờ reply -> dự đoán.
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
        # Chuyển FlowStatsReply thành bản ghi dạng bảng cho mô hình ML.
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        
        # Chỉ đưa flow chuyển tiếp exact-match priority 1 vào ML. Flow DROP priority
        # 80 và hard-isolation priority 100 đã bị chặn nên không cần AI dự đoán.
        inspected_flows = [flow for flow in body if flow.priority == 1]

        new_entries = []
        for stat in inspected_flows:
            if 'ipv4_src' not in stat.match:
                continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match.get('ipv4_dst', 'ANY')
            ip_proto = stat.match.get('ip_proto', 0)
            flow_priority = stat.priority
            if self.policy_engine.get_mitigation_action(ip_src) == "ADAPTIVE_MICROSEGMENTATION":
                zta_enforcement = "ADAPTIVE_EXACT_METER"
            else:
                zta_enforcement = "NORMAL_FORWARD"
            
            icmp_code = -1
            icmp_type = -1
            tp_src = 0
            tp_dst = 0

            # Chuẩn hóa trường tầng giao vận: ICMP dùng type/code, TCP/UDP dùng port.
            if ip_proto == 1:
                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)
            elif ip_proto == 6:
                tp_src = stat.match.get('tcp_src', 0)
                tp_dst = stat.match.get('tcp_dst', 0)
            elif ip_proto == 17:
                tp_src = stat.match.get('udp_src', 0)
                tp_dst = stat.match.get('udp_dst', 0)

            # Thêm priority để flow normal và flow enforcement không dùng chung counter.
            flow_id = f"{flow_priority}:{ip_src}:{tp_src}:{ip_dst}:{tp_dst}:{ip_proto}"
            self.current_cycle_flow_ids.add(flow_id)

            current_packets = stat.packet_count
            last_packets = self.last_flow_packets.get(flow_id, -1)
            
            # Counter giảm nghĩa là flow đã bị xóa/tạo lại, xử lý như flow mới.
            if last_packets != -1 and current_packets < last_packets:
                last_packets = -1
                
            delta_packets = current_packets - last_packets if last_packets != -1 else current_packets

            # Bỏ qua flow cũ gần như không phát sinh lưu lượng mới.
            if last_packets != -1 and delta_packets <= 2:
                continue

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
                'flow_priority': flow_priority,
                'zta_enforcement': zta_enforcement,
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

        if new_entries:
            with self.stats_lock:
                self.flow_stats_buffer.extend(new_entries)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        # Ghi đè add_flow để có thể gắn Meter vào flow bị hạn chế.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Flow ngoài whitelist trong microsegment được nâng priority để DROP sớm.
        flow_priority = priority
        if priority == 1 and 'ipv4_src' in match and not actions:
            flow_priority = 80

        inst = []
        
        # Flow được phép của host bị hạn chế sẽ đi qua Meter ID 1.
        if priority == 1 and 'ipv4_src' in match:
            src_ip = match['ipv4_src']
            if actions and self.policy_engine.get_mitigation_action(src_ip) in ("RATE_LIMITING", "ADAPTIVE_MICROSEGMENTATION"):
                inst.append(parser.OFPInstructionMeter(meter_id=1))

        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=flow_priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=flow_priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            
        datapath.send_msg(mod)

    def filter_flow_actions(self, datapath, match, actions):
        if 'ipv4_src' not in match:
            return actions

        src_ip = match['ipv4_src']
        if self.policy_engine.get_mitigation_action(src_ip) != "ADAPTIVE_MICROSEGMENTATION":
            return actions

        if self.mitigation_executor.is_microsegment_allowed(match):
            return actions

        return []

    def flow_predict(self):
        # Lấy snapshot buffer để mỗi chu kỳ chỉ dự đoán dữ liệu mới.
        with self.stats_lock:
            copied_stats = list(self.flow_stats_buffer)
            self.flow_stats_buffer.clear()

        try:
            if len(copied_stats) == 0:
                # Chu kỳ yên tĩnh: phục hồi trust score và đánh giá lại host bị hạn chế.
                for ip in list(self.policy_engine.get_all_trust_scores().keys()):
                    self.policy_engine.apply_recovery(ip)
                self.print_trust_scores_report(stats={}, total_flows=0)
                
                for ip in list(self.mitigation_executor.restricted_ips):
                    action = self.policy_engine.get_mitigation_action(ip)
                    if action == "HARD_ISOLATION":
                        self.mitigation_executor.apply_hard_isolation(ip)
                    elif action == "ADAPTIVE_MICROSEGMENTATION":
                        self.mitigation_executor.apply_adaptive_microsegmentation(ip)
                    else:
                        self.mitigation_executor.remove_restrictions(ip)
                return

            predict_flow_dataset = pd.DataFrame(copied_stats)

            # Đặc trưng tổng hợp theo IP nguồn giúp nhận biết DDoS/DoS/Port Scan.
            flow_counts = predict_flow_dataset.groupby('ip_src').size().to_dict()
            incoming_counts = predict_flow_dataset.groupby('ip_dst').size().to_dict()
            packet_rates = predict_flow_dataset.groupby('ip_src')['packet_count_per_second'].sum().to_dict()
            unique_ports = predict_flow_dataset.groupby('ip_src')['tp_dst'].nunique().to_dict()

            df_clean = predict_flow_dataset.copy()
            df_clean['flow_count_src'] = df_clean['ip_src'].map(flow_counts)
            df_clean['packet_rate_src'] = df_clean['ip_src'].map(packet_rates)
            df_clean['unique_dst_ports_src'] = df_clean['ip_src'].map(unique_ports)

            predictions, probs = self.ml_engine.predict(df_clean)

            active_ips = set(predict_flow_dataset['ip_src'].unique())

            # Gom thống kê báo cáo và penalty theo từng host trong chu kỳ.
            stats = {name: 0 for name in self.label_names.values()}
            active_flows_summary = {}
            host_risks = {ip: [] for ip in active_ips}

            for idx, pred in enumerate(predictions):
                ip_src = predict_flow_dataset.iloc[idx]['ip_src']
                ip_dst = predict_flow_dataset.iloc[idx]['ip_dst']
                flow_priority = int(predict_flow_dataset.iloc[idx].get('flow_priority', 1))
                zta_enforcement = predict_flow_dataset.iloc[idx].get('zta_enforcement', 'NORMAL_FORWARD')
                prob = probs[idx][pred]

                # Dự đoán tấn công dưới 50% confidence được hạ về BENIGN.
                if pred > 0 and prob < 0.50:
                    pred = 0
                    prob = 1.0 - prob

                label_name = self.label_names.get(pred, 'UNKNOWN')
                stats[label_name] = stats.get(label_name, 0) + 1

                # Gom nhóm để báo cáo active flow ngắn gọn.
                flow_key = (ip_src, ip_dst, label_name, flow_priority, zta_enforcement)
                if flow_key not in active_flows_summary:
                    active_flows_summary[flow_key] = {'count': 0, 'probs': []}
                active_flows_summary[flow_key]['count'] += 1
                active_flows_summary[flow_key]['probs'].append(prob)

                # Kết hợp xác suất ML với rủi ro ngữ cảnh AAA để tính penalty.
                context_risk = self.identity_analyzer.get_context_risk_score(ip_src)
                combined_risk = self.identity_analyzer.combine_ml_and_context(prob, context_risk)
                severity_weight = self.attack_severity_weights.get(pred, 0.0)
                penalty = severity_weight * combined_risk
                if penalty > 0:
                    host_risks[ip_src].append(penalty)

            safe_hosts = set()

            for ip, penalties in host_risks.items():
                if penalties:
                    # Chỉ trừ penalty lớn nhất để tránh phạt quá mạnh trong một chu kỳ.
                    self.policy_engine.update_trust_score(ip, max(penalties))
                else:
                    safe_hosts.add(ip)

            for ip in safe_hosts:
                self.policy_engine.apply_recovery(ip)

            self.print_trust_scores_report(stats, len(predictions), active_flows_summary)

            # Áp dụng chính sách cho IP đang hoạt động và IP còn bị hạn chế.
            all_target_ips = active_ips.union(self.mitigation_executor.restricted_ips)
            for ip in all_target_ips:
                action = self.policy_engine.get_mitigation_action(ip)
                if action == "HARD_ISOLATION":
                    self.mitigation_executor.apply_hard_isolation(ip)
                elif action == "ADAPTIVE_MICROSEGMENTATION":
                    self.mitigation_executor.apply_adaptive_microsegmentation(ip)
                else:
                    self.mitigation_executor.remove_restrictions(ip)

        except Exception as e:
            self.logger.error("Lỗi trong quá trình dự đoán lưu lượng ZTA: %s", str(e))
        finally:
            # Dọn counter của flow đã biến mất khỏi chu kỳ hiện tại.
            for fid in list(self.last_flow_packets.keys()):
                if fid not in self.current_cycle_flow_ids:
                    del self.last_flow_packets[fid]
            self.current_cycle_flow_ids.clear()

    def print_trust_scores_report(self, stats, total_flows, active_flows_summary=None):
        role_annotations = {
            '10.0.0.1': ' (SV WEB 1)',
            '10.0.0.2': ' (SV WEB 2)',
            '10.0.0.3': ' (DNS 1)',
            '10.0.0.4': ' (DNS 2)',
            '10.0.0.5': ' (DB 1)',
            '10.0.0.6': ' (DB 2)',
            '10.0.0.7': ' (USER)',
            '10.0.0.8': ' (USER)'
        }
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Đổi màu tiêu đề theo trạng thái chung của chu kỳ.
        has_attack = any(stats.get(name, 0) > 0 for name in stats if name != 'BENIGN')
        color = "\033[91m" if has_attack else "\033[92m"
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
            for flow_key, info in sorted(active_flows_summary.items()):
                if len(flow_key) == 5:
                    ip_src, ip_dst, label_name, flow_priority, zta_enforcement = flow_key
                else:
                    ip_src, ip_dst, label_name = flow_key
                    flow_priority = 1
                    zta_enforcement = 'NORMAL_FORWARD'
                count = info['count']
                avg_prob = sum(info['probs']) / len(info['probs']) if info['probs'] else 0.0
                self.logger.info("  - [%s] -> [%s] | Prio: %s | ZTA: %s | Nhãn: %s (%d flows) | Độ tin cậy của AI: %.1f%%",
                                 ip_src, ip_dst, flow_priority, zta_enforcement, label_name, count, avg_prob * 100)
        
        self.logger.info("---------------------------------------------------------------------")
        self.logger.info("BẢNG ĐIỂM TIN CẬY ĐỘNG (DYNAMIC TRUST SCORE):")
        
        scores = self.policy_engine.get_all_trust_scores()
        for ip, score in sorted(scores.items()):
            role = role_annotations.get(ip, '')
            action = self.policy_engine.get_mitigation_action(ip)
            
            if action == "HARD_ISOLATION":
                status = "\033[91mCÁCH LY CỨNG\033[0m"
            elif action == "ADAPTIVE_MICROSEGMENTATION":
                status = "\033[93mMICROSEGMENT + RATE LIMIT\033[0m"
            else:
                status = "\033[92mAN TOÀN\033[0m"
                
            self.logger.info("  - Host %-15s%s: Trust Score = %.2f [%s]", ip, role, score, status)
        self.logger.info("%s=====================================================================%s", color, reset)
