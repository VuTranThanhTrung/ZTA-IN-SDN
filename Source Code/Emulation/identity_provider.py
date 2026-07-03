import json
import os
from typing import Dict, Any, Optional


class MockAAAServer:
    """AAA giả lập: ánh xạ IP sang thông tin người dùng và thiết bị."""

    def __init__(self, config_path: str, logger: Any = None) -> None:
        self.config_path: str = config_path
        self.logger: Any = logger
        self.user_db: Dict[str, Dict[str, Any]] = {}
        self.device_db: Dict[str, Dict[str, Any]] = {}
        self.load_config()

    def load_config(self) -> None:
        """Nạp dữ liệu AAA từ JSON, hoặc tạo dữ liệu mặc định nếu file thiếu."""
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

        # Dữ liệu dự phòng cho topology 8 host trong Mininet.
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

        # Ghi lại file JSON để các lần chạy sau dùng cùng dữ liệu.
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.config_path)), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({'users': self.user_db, 'devices': self.device_db}, f, indent=4)
        except Exception as e:
            if self.logger:
                self.logger.warning("[!] Ghi file cấu hình AAA dự phòng thất bại: %s", str(e))


class IdentityContextAnalyzer:
    """Tính rủi ro ngữ cảnh từ dữ liệu AAA cho chính sách Zero Trust."""

    def __init__(self, aaa_server: MockAAAServer, logger: Any = None) -> None:
        self.aaa_server: MockAAAServer = aaa_server
        self.logger: Any = logger
        # Role càng ít tin cậy thì risk càng cao.
        self.role_risk_scores: Dict[str, float] = {
            'system': 0.25,
            'employee': 0.50,
            'guest': 0.75
        }

    def get_user_context(self, ip_address: str) -> Dict[str, Any]:
        """Trả thông tin người dùng gắn với IP."""
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
        """Trả trạng thái thiết bị gắn với IP."""
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
        """Tính điểm rủi ro ngữ cảnh theo role của host."""
        try:
            user = self.get_user_context(ip_address)
            role = user.get('role', 'guest')

            # Mô hình hiện tại chỉ dùng role; posture vẫn giữ để phục vụ mở rộng.
            risk: float = self.role_risk_scores.get(role, self.role_risk_scores['guest'])

            return max(0.0, min(1.0, risk))
        except Exception as e:
            if self.logger:
                self.logger.error("Lỗi khi tính toán điểm rủi ro ngữ cảnh cho %s: %s", ip_address, str(e))
            return self.role_risk_scores['guest']

    def combine_ml_and_context(self, ml_confidence: float, context_risk: float) -> float:
        """Kết hợp độ tin cậy ML và rủi ro ngữ cảnh thành combined risk."""
        combined: float = (0.6 * ml_confidence) + (0.4 * context_risk)
        return max(0.0, min(1.0, combined))

    def explain_decision(self, ip_address: str, ml_pred: int, combined_risk: float) -> Dict[str, Any]:
        """Tạo dữ liệu giải thích quyết định để log/báo cáo."""
        user = self.get_user_context(ip_address)

        return {
            'ip_address': ip_address,
            'ml_prediction_class': int(ml_pred),
            'combined_risk': float(combined_risk),
            'user_role': user.get('role', 'guest'),
            'timestamp': os.times()[4] if hasattr(os, 'times') else 0.0
        }
