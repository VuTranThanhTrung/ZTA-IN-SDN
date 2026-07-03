from typing import Dict, Any

# Mitigation Executor là tầng thực thi của kiến trúc: nhận quyết định từ Policy Engine
# và chuyển quyết định đó thành các bản tin OpenFlow gửi xuống switch.

class MitigationExecutor:
    WEB_SERVERS = {"10.0.0.1", "10.0.0.2"}
    DNS_SERVERS = {"10.0.0.3", "10.0.0.4"}
    DB_SERVERS = {"10.0.0.5", "10.0.0.6"}
    USER_HOSTS = {"10.0.0.7", "10.0.0.8"}

    def __init__(self, datapaths: Dict[int, Any], logger: Any = None) -> None:
        # datapaths được truyền theo tham chiếu từ controller, vì vậy danh sách switch
        # mới kết nối/ngắt kết nối luôn được cập nhật mà không cần tạo lại executor.
        self.datapaths: Dict[int, Any] = datapaths
        self.logger: Any = logger
        # restricted_ips hỗ trợ controller duyệt nhanh; restriction_states lưu chính xác
        # IP đang bị cách ly cứng hay đang bị vi phân đoạn thích ứng.
        self.restricted_ips = set()
        self.restriction_states: Dict[str, str] = {}

    def _sync_restricted_set(self) -> None:
        # Đồng bộ tập IP bị hạn chế từ nguồn trạng thái chính restriction_states.
        self.restricted_ips = set(self.restriction_states.keys())

    def _delete_ip_flows(self, datapath: Any, attacker_ip: str, delete_src: bool = True, delete_dst: bool = True) -> None:
        # Xóa các flow IPv4 đã học liên quan đến IP. Sau khi bị xóa, packet tiếp theo
        # sẽ quay lại controller để được cài luật mới phù hợp với chính sách hiện tại.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if delete_src:
            # Xóa mọi flow có IP này là nguồn, tức chiều lưu lượng đi ra từ host.
            match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            mod_out = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                table_id=ofproto.OFPTT_ALL,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match_out
            )
            datapath.send_msg(mod_out)

        if delete_dst:
            # Xóa mọi flow có IP này là đích, tức chiều lưu lượng đi vào host.
            match_in = parser.OFPMatch(eth_type=0x0800, ipv4_dst=attacker_ip)
            mod_in = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                table_id=ofproto.OFPTT_ALL,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match_in
            )
            datapath.send_msg(mod_in)

    def configure_meter(self, datapath: Any, meter_id: int, rate: int) -> bool:
        try:
            # Meter dùng đơn vị packet/giây (OFPMF_PKTPS). Khi vượt rate, band DROP
            # sẽ loại packet; burst_size cho phép một lượng bùng nổ ngắn.
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
            if self.logger:
                self.logger.info("[ZTA METER] Đã cấu hình meter_id=%d trên switch=%016x với tốc độ=%dpps",
                                 meter_id, datapath.id, rate)
            return True
        except Exception as e:
            if self.logger:
                self.logger.error("[!] Cấu hình meter_id=%d trên switch=%016x thất bại: %s",
                                 meter_id, datapath.id, str(e))
            return False

    def _send_flow(self, datapath: Any, priority: int, match: Any, actions: list,
                   meter_id: int = None, idle: int = 0, hard: int = 0) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id=meter_id))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle,
            hard_timeout=hard,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def is_microsegment_allowed(self, match: Any) -> bool:
        ip_src = match.get('ipv4_src')
        ip_dst = match.get('ipv4_dst')
        ip_proto = match.get('ip_proto', 0)
        tcp_src = match.get('tcp_src', 0)
        tcp_dst = match.get('tcp_dst', 0)
        udp_src = match.get('udp_src', 0)
        udp_dst = match.get('udp_dst', 0)

        # User/guest/employee: chỉ giữ quyền tối thiểu tới Web và DNS.
        if ip_src in self.USER_HOSTS or ip_src not in (
            self.WEB_SERVERS | self.DNS_SERVERS | self.DB_SERVERS
        ):
            if ip_dst in self.WEB_SERVERS and ip_proto == 6 and tcp_dst in (80, 443):
                return True
            if ip_dst in self.DNS_SERVERS and ip_proto == 17 and udp_dst == 53:
                return True
            if ip_dst in self.DNS_SERVERS and ip_proto == 6 and tcp_dst == 53:
                return True
            return False

        # Web server: vẫn được trả lời HTTP/HTTPS và đi tới DB qua port 3306.
        if ip_src in self.WEB_SERVERS:
            if ip_proto == 6 and tcp_src in (80, 443):
                return True
            if ip_dst in self.DB_SERVERS and ip_proto == 6 and tcp_dst == 3306:
                return True
            return False

        # DNS server: chỉ giữ các chiều truy vấn/phản hồi DNS.
        if ip_src in self.DNS_SERVERS:
            if ip_proto == 6 and (tcp_src == 53 or tcp_dst == 53):
                return True
            if ip_proto == 17 and (udp_src == 53 or udp_dst == 53):
                return True
            return False

        # DB server: chỉ giữ phản hồi MySQL về Web zone và đồng bộ DB nội bộ.
        if ip_src in self.DB_SERVERS:
            if ip_dst in self.WEB_SERVERS and ip_proto == 6 and tcp_src == 3306:
                return True
            if ip_dst in (self.DB_SERVERS - {ip_src}):
                return True
            return False

        return False

    def apply_hard_isolation(self, attacker_ip: str) -> bool:
        # Không thể thực thi chính sách nếu chưa có switch OpenFlow kết nối.
        if not self.datapaths:
            if self.logger:
                self.logger.warning("[!] Không có switch nào đang kết nối. Không thể áp dụng cách ly.")
            return False

        # Tránh gửi lặp lại cùng luật nếu IP đã ở đúng trạng thái cách ly.
        if self.restriction_states.get(attacker_ip) == "HARD_ISOLATION":
            return True

        if self.logger:
            self.logger.error("[ZTA POLICY - HARD ISOLATION] Đang cách ly hoàn toàn IP: %s", attacker_ip)

        success = True
        # Áp dụng trên tất cả switch để host không thể đi vòng qua switch khác.
        for dp in list(self.datapaths.values()):
            try:
                ofproto = dp.ofproto
                parser = dp.ofproto_parser

                # Rule 1: DROP traffic coming from the attacker
                # Action rỗng trong OpenFlow tương đương DROP. Priority 100 cao hơn
                # flow chuyển tiếp priority 1 nên luật cách ly luôn được ưu tiên.
                match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
                inst_out = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                mod_out = parser.OFPFlowMod(
                    datapath=dp, priority=100, idle_timeout=0, hard_timeout=0,
                    match=match_out, instructions=inst_out
                )
                dp.send_msg(mod_out)

                # Rule 2: DROP traffic going to the attacker
                # Chặn cả chiều vào để cô lập hoàn toàn host khỏi phần mạng còn lại.
                match_in = parser.OFPMatch(eth_type=0x0800, ipv4_dst=attacker_ip)
                inst_in = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                mod_in = parser.OFPFlowMod(
                    datapath=dp, priority=100, idle_timeout=0, hard_timeout=0,
                    match=match_in, instructions=inst_in
                )
                dp.send_msg(mod_in)

            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Áp dụng cách ly trên switch %016x thất bại: %s", dp.id, str(e))
                success = False

        # Chỉ ghi nhận trạng thái mới khi mọi switch đều nhận lệnh thành công.
        if success:
            self.restriction_states[attacker_ip] = "HARD_ISOLATION"
            self._sync_restricted_set()
        return success

    def apply_adaptive_microsegmentation(self, attacker_ip: str) -> bool:
        if not self.datapaths:
            if self.logger:
                self.logger.warning("[!] Không có switch nào đang kết nối. Không thể áp dụng vi phân đoạn thích ứng.")
            return False

        # Tránh xóa và tái tạo flow không cần thiết nếu chính sách không thay đổi.
        if self.restriction_states.get(attacker_ip) == "ADAPTIVE_MICROSEGMENTATION":
            return True

        if self.logger:
            self.logger.warning("[ZTA POLICY - ADAPTIVE MICROSEGMENTATION] Đang siết quyền truy cập IP: %s", attacker_ip)

        success = True
        for dp in list(self.datapaths.values()):
            try:
                # If the host was hard-isolated before, remove both DROP directions first.
                # Khi hạ từ cách ly cứng xuống vi phân đoạn thích ứng, phải xóa hai
                # luật DROP priority 100 trước để host có thể truyền dữ liệu tối thiểu.
                if self.restriction_states.get(attacker_ip) == "HARD_ISOLATION":
                    self._delete_ip_flows(dp, attacker_ip, delete_src=True, delete_dst=True)

                # Xóa flow chiều đi cũ. Từ thời điểm này, các packet mới sẽ quay lại
                # controller; flow hợp lệ được cài exact-match kèm Meter, flow ngoài
                # whitelist bị cài DROP exact-match qua hook filter_flow_actions().
                self._delete_ip_flows(dp, attacker_ip, delete_src=True, delete_dst=False)
            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Áp dụng vi phân đoạn thích ứng trên switch %016x thất bại: %s", dp.id, str(e))
                success = False

        # Cập nhật trạng thái sau khi thao tác đã thành công trên toàn bộ switch.
        if success:
            self.restriction_states[attacker_ip] = "ADAPTIVE_MICROSEGMENTATION"
            self._sync_restricted_set()
        return success

    def apply_rate_limiting(self, attacker_ip: str) -> bool:
        # Giữ alias tương thích với tên cũ: vùng điểm giữa giờ là vi phân đoạn
        # thích ứng kèm Meter, không còn chỉ bóp băng thông đơn thuần.
        return self.apply_adaptive_microsegmentation(attacker_ip)

    def remove_restrictions(self, attacker_ip: str) -> bool:
        if not self.datapaths:
            if self.logger:
                self.logger.warning("[!] Không có switch nào đang kết nối. Không thể gỡ bỏ giới hạn.")
            return False

        # IP không nằm trong tập hạn chế thì không cần gửi FlowMod xuống switch.
        if attacker_ip not in self.restricted_ips:
            return True

        if self.logger:
            self.logger.info("[ZTA POLICY - RESTORE] Đang khôi phục quyền truy cập cho IP: %s", attacker_ip)

        success = True
        for dp in list(self.datapaths.values()):
            try:
                # Xóa cả luật DROP lẫn flow có Meter còn tồn tại. Packet tiếp theo sẽ
                # được controller cài lại như một flow ALLOW thông thường.
                self._delete_ip_flows(dp, attacker_ip, delete_src=True, delete_dst=True)
            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Gỡ bỏ giới hạn trên switch %016x thất bại: %s", dp.id, str(e))
                success = False

        # Chỉ xóa trạng thái nội bộ khi việc khôi phục đã thành công ở mọi switch.
        if success:
            self.restriction_states.pop(attacker_ip, None)
            self.restricted_ips.discard(attacker_ip)
        return success
