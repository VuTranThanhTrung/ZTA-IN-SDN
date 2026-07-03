import json
import os
from typing import Dict, Any, Optional

class MockAAAServer:
    """
    MockAAAServer simulates an Authentication, Authorization, and Accounting server
    that manages user identities and device metadata mapped to IP addresses.
    """
    def __init__(self, config_path: str, logger: Any = None) -> None:
        """
        Initialize the Mock AAA Server.

        Args:
            config_path: Path to the JSON configuration file containing user data.
            logger: Optional logger instance.
        """
        self.config_path: str = config_path
        self.logger: Any = logger
        self.user_db: Dict[str, Dict[str, Any]] = {}
        self.device_db: Dict[str, Dict[str, Any]] = {}
        self.load_config()

    def load_config(self) -> None:
        """
        Load AAA configuration from config_path or initialize default fallback data.
        """
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.user_db = data.get('users', {})
                    self.device_db = data.get('devices', {})
                if self.logger:
                    self.logger.info("[+] Đã nạp thành công cấu hình Mock AAA từ %s", self.config_path)
                return
            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Tải cấu hình AAA từ %s thất bại: %s", self.config_path, str(e))

        # Fallback default emulation data if file is missing
        if self.logger:
            self.logger.warning("[!] Không tìm thấy file cấu hình AAA %s. Đang nạp cơ sở dữ liệu giả lập dự phòng.", self.config_path)
        
        self.user_db = {
            '10.0.0.1': {'username': 'web_server_1', 'role': 'system', 'clearance': 'high'},
            '10.0.0.2': {'username': 'web_server_2', 'role': 'system', 'clearance': 'high'},
            '10.0.0.3': {'username': 'dns_server_1', 'role': 'system', 'clearance': 'high'},
            '10.0.0.4': {'username': 'dns_server_2', 'role': 'system', 'clearance': 'high'},
            '10.0.0.5': {'username': 'db_server_1', 'role': 'system', 'clearance': 'high'},
            '10.0.0.6': {'username': 'db_server_2', 'role': 'system', 'clearance': 'high'},
            '10.0.0.7': {'username': 'employee_user', 'role': 'employee', 'clearance': 'medium'},
            '10.0.0.8': {'username': 'anonymous_user', 'role': 'guest', 'clearance': 'low'}
        }
        self.device_db = {
            '10.0.0.1': {'os': 'Linux', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.2': {'os': 'Linux', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.3': {'os': 'Linux', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.4': {'os': 'Linux', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.5': {'os': 'Linux', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.6': {'os': 'Linux', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.7': {'os': 'Windows', 'compliant': True, 'certificates': 'valid'},
            '10.0.0.8': {'os': 'Unknown', 'compliant': False, 'certificates': 'none'}
        }

        # Save default data to create config_path
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.config_path)), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({'users': self.user_db, 'devices': self.device_db}, f, indent=4)
        except Exception as e:
            if self.logger:
                self.logger.warning("[!] Ghi file cấu hình AAA dự phòng thất bại: %s", str(e))


class IdentityContextAnalyzer:
    """
    IdentityContextAnalyzer integrates with a MockAAAServer to provide user context
    and calculate risk scores for zero-trust policies.
    """
    def __init__(self, aaa_server: MockAAAServer, logger: Any = None) -> None:
        """
        Initialize the Identity Context Analyzer.

        Args:
            aaa_server: The AAA Server instance to fetch identity data from.
            logger: Optional logger instance.
        """
        self.aaa_server: MockAAAServer = aaa_server
        self.logger: Any = logger
        self.role_risk_scores: Dict[str, float] = {
            'system': 0.25,
            'employee': 0.50,
            'guest': 0.75
        }

    def get_user_context(self, ip_address: str) -> Dict[str, Any]:
        """
        Get user context associated with the IP address.

        Args:
            ip_address: The IP address of the host.

        Returns:
            A JSON-serializable dictionary with user context fields.
        """
        try:
            if ip_address in self.aaa_server.user_db:
                return self.aaa_server.user_db[ip_address]
            else:
                if self.logger:
                    self.logger.warning("Địa chỉ IP không xác định đang yêu cầu thông tin người dùng: %s", ip_address)
                return {'username': 'unknown', 'role': 'unknown', 'clearance': 'none'}
        except Exception as e:
            if self.logger:
                self.logger.error("Lỗi khi truy xuất thông tin người dùng cho %s: %s", ip_address, str(e))
            return {'username': 'unknown', 'role': 'unknown', 'clearance': 'none'}

    def get_device_posture(self, ip_address: str) -> Dict[str, Any]:
        """
        Get device posture associated with the IP address.

        Args:
            ip_address: The IP address of the host.

        Returns:
            A JSON-serializable dictionary with device posture fields.
        """
        try:
            if ip_address in self.aaa_server.device_db:
                return self.aaa_server.device_db[ip_address]
            else:
                if self.logger:
                    self.logger.warning("Địa chỉ IP không xác định đang yêu cầu thông tin thiết bị: %s", ip_address)
                return {'os': 'unknown', 'compliant': False, 'certificates': 'none'}
        except Exception as e:
            if self.logger:
                self.logger.error("Lỗi khi truy xuất thông tin thiết bị cho %s: %s", ip_address, str(e))
            return {'os': 'unknown', 'compliant': False, 'certificates': 'none'}

    def get_context_risk_score(self, ip_address: str) -> float:
        """
        Calculate context risk score from the AAA role assigned to the host.

        Args:
            ip_address: The IP address of the host.

        Returns:
            A float value representing the risk score, bounded between 0.0 and 1.0.
        """
        try:
            user = self.get_user_context(ip_address)
            role = user.get('role', 'guest')

            # Role-only context model:
            # system = 0.25, employee = 0.50, guest = 0.75.
            # Device compliance is kept as AAA metadata but is not part of this
            # simulated scoring formula.
            risk: float = self.role_risk_scores.get(role, self.role_risk_scores['guest'])

            return max(0.0, min(1.0, risk))
        except Exception as e:
            if self.logger:
                self.logger.error("Lỗi khi tính toán điểm rủi ro ngữ cảnh cho %s: %s", ip_address, str(e))
            return self.role_risk_scores['guest']

    def combine_ml_and_context(self, ml_confidence: float, context_risk: float) -> float:
        """
        Combine machine learning classification confidence with context risk score.

        Args:
            ml_confidence: The confidence score from the ML model.
            context_risk: The context risk score.

        Returns:
            A combined risk score, bounded between 0.0 and 1.0.
        """
        combined: float = (0.6 * ml_confidence) + (0.4 * context_risk)
        return max(0.0, min(1.0, combined))

    def explain_decision(self, ip_address: str, ml_pred: int, combined_risk: float) -> Dict[str, Any]:
        """
        Explain the combined trust/risk decision for reporting and audits.

        Args:
            ip_address: The IP address of the host.
            ml_pred: The ML predicted class index.
            combined_risk: The calculated combined risk score.

        Returns:
            A JSON-serializable dictionary detailing the explanation.
        """
        user = self.get_user_context(ip_address)

        return {
            'ip_address': ip_address,
            'ml_prediction_class': int(ml_pred),
            'combined_risk': float(combined_risk),
            'user_role': user.get('role', 'guest'),
            'timestamp': os.times()[4] if hasattr(os, 'times') else 0.0
        }
