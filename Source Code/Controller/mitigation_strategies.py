from typing import Dict, Any

class MitigationExecutor:
    """
    MitigationExecutor executes OpenFlow flow rules and meter configurations
    for zero-trust security policy enforcement.
    """
    def __init__(self, datapaths: Dict[int, Any], logger: Any = None) -> None:
        """
        Initialize the Mitigation Executor.

        Args:
            datapaths: A dictionary mapping datapath IDs to Ryu datapath objects.
            logger: Optional logger instance.
        """
        self.datapaths: Dict[int, Any] = datapaths
        self.logger: Any = logger
        self.restricted_ips = set()
        self.restriction_states: Dict[str, str] = {}

    def _sync_restricted_set(self) -> None:
        self.restricted_ips = set(self.restriction_states.keys())

    def _delete_ip_flows(self, datapath: Any, attacker_ip: str, delete_src: bool = True, delete_dst: bool = True) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if delete_src:
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
        """
        Configure an OpenFlow Meter to limit packet rates.

        Args:
            datapath: The Ryu datapath object.
            meter_id: The ID of the meter to configure.
            rate: The rate limit in packets per second (pps).

        Returns:
            True if configuration message was sent successfully, False otherwise.
        """
        try:
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

    def apply_hard_isolation(self, attacker_ip: str) -> bool:
        """
        Apply hard isolation (DROP rules) for the attacker IP.

        Args:
            attacker_ip: The IP address to isolate.

        Returns:
            True if all rules were sent successfully, False otherwise.
        """
        if not self.datapaths:
            if self.logger:
                self.logger.warning("[!] Không có switch nào đang kết nối. Không thể áp dụng cách ly.")
            return False

        if self.restriction_states.get(attacker_ip) == "HARD_ISOLATION":
            return True

        if self.logger:
            self.logger.error("[ZTA POLICY - HARD ISOLATION] Đang cách ly hoàn toàn IP: %s", attacker_ip)

        success = True
        for dp in list(self.datapaths.values()):
            try:
                ofproto = dp.ofproto
                parser = dp.ofproto_parser

                # Rule 1: DROP traffic coming from the attacker
                match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
                inst_out = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                mod_out = parser.OFPFlowMod(
                    datapath=dp, priority=100, idle_timeout=0, hard_timeout=0,
                    match=match_out, instructions=inst_out
                )
                dp.send_msg(mod_out)

                # Rule 2: DROP traffic going to the attacker
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

        if success:
            self.restriction_states[attacker_ip] = "HARD_ISOLATION"
            self._sync_restricted_set()
        return success

    def apply_rate_limiting(self, attacker_ip: str) -> bool:
        """
        Apply rate limiting by deleting existing outbound flows of the attacker.
        This forces subsequent packets to return to the controller for
        re-evaluation instead of continuing on stale learned entries.

        Args:
            attacker_ip: The IP address to throttle.

        Returns:
            True if all operations were sent successfully, False otherwise.
        """
        if not self.datapaths:
            if self.logger:
                self.logger.warning("[!] Không có switch nào đang kết nối. Không thể áp dụng bóp băng thông.")
            return False

        if self.restriction_states.get(attacker_ip) == "RATE_LIMITING":
            return True

        if self.logger:
            self.logger.warning("[ZTA POLICY - RATE LIMITING] Đang giới hạn băng thông IP: %s", attacker_ip)

        success = True
        for dp in list(self.datapaths.values()):
            try:
                # If the host was hard-isolated before, remove both DROP directions first.
                if self.restriction_states.get(attacker_ip) == "HARD_ISOLATION":
                    self._delete_ip_flows(dp, attacker_ip, delete_src=True, delete_dst=True)

                self._delete_ip_flows(dp, attacker_ip, delete_src=True, delete_dst=False)
            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Áp dụng bóp băng thông trên switch %016x thất bại: %s", dp.id, str(e))
                success = False

        if success:
            self.restriction_states[attacker_ip] = "RATE_LIMITING"
            self._sync_restricted_set()
        return success

    def remove_restrictions(self, attacker_ip: str) -> bool:
        """
        Remove restrictions (DROP and rate limiting flows) for the given IP address.

        Args:
            attacker_ip: The IP address to restore.

        Returns:
            True if restrictions were removed successfully, False otherwise.
        """
        if not self.datapaths:
            if self.logger:
                self.logger.warning("[!] Không có switch nào đang kết nối. Không thể gỡ bỏ giới hạn.")
            return False

        if attacker_ip not in self.restricted_ips:
            return True

        if self.logger:
            self.logger.info("[ZTA POLICY - RESTORE] Đang khôi phục quyền truy cập cho IP: %s", attacker_ip)

        success = True
        for dp in list(self.datapaths.values()):
            try:
                self._delete_ip_flows(dp, attacker_ip, delete_src=True, delete_dst=True)
            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Gỡ bỏ giới hạn trên switch %016x thất bại: %s", dp.id, str(e))
                success = False

        if success:
            self.restriction_states.pop(attacker_ip, None)
            self.restricted_ips.discard(attacker_ip)
        return success
