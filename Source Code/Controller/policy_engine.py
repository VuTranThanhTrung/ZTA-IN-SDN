import datetime
from threading import Lock
from typing import Dict, Any

# Policy Engine là cầu nối giữa kết quả đánh giá rủi ro và hành động trên mạng.
# Mỗi host có trust score trong [0, 1]: càng thấp thì mức độ hạn chế càng cao.

class DynamicPolicyEngine:
    def __init__(self, logger: Any = None, recovery_step: float = 0.02) -> None:
        self.logger: Any = logger
        # trust_scores lưu điểm hiện tại theo IP; penalties_count phục vụ giải thích
        # số lần host đã bị áp dụng penalty.
        self.trust_scores: Dict[str, float] = {}
        self.penalties_count: Dict[str, int] = {}
        # Mỗi chu kỳ an toàn, điểm tin cậy được phục hồi thêm recovery_step.
        self.recovery_step: float = recovery_step
        # Lock bảo vệ dữ liệu vì Policy Engine được truy cập từ các luồng sự kiện Ryu.
        self.lock: Lock = Lock()

    def update_trust_score(self, ip_address: str, penalty: float) -> float:
        with self.lock:
            # Host xuất hiện lần đầu được giả định tin cậy hoàn toàn theo thang điểm 1.0.
            if ip_address not in self.trust_scores:
                self.trust_scores[ip_address] = 1.0
                self.penalties_count[ip_address] = 0

            old_score: float = self.trust_scores[ip_address]
            # Trừ penalty nhưng luôn chặn kết quả trong miền hợp lệ [0.0, 1.0].
            new_score: float = max(0.0, min(1.0, old_score - penalty))
            self.trust_scores[ip_address] = new_score

            # Chỉ tăng bộ đếm khi thật sự có hình phạt, không tính các lần khởi tạo.
            if penalty > 0:
                self.penalties_count[ip_address] += 1

            return new_score

    def get_mitigation_action(self, ip_address: str) -> str:
        with self.lock:
            # Host chưa có lịch sử được xem là tin cậy với score mặc định 1.0.
            score: float = self.trust_scores.get(ip_address, 1.0)
            # Ba vùng quyết định:
            # [0.00, 0.40): cách ly; [0.40, 0.85): vi phân đoạn thích ứng;
            # [0.85, 1.00]: cho phép.
            if score < 0.40:
                return "HARD_ISOLATION"
            elif score < 0.85:
                return "ADAPTIVE_MICROSEGMENTATION"
            else:
                return "ALLOW"

    def apply_recovery(self, ip_address: str) -> None:
        with self.lock:
            # Nếu IP chưa tồn tại thì khởi tạo ở mức an toàn, không cần cộng phục hồi.
            if ip_address not in self.trust_scores:
                self.trust_scores[ip_address] = 1.0
                return

            old_score: float = self.trust_scores[ip_address]
            # Phục hồi từ từ và không cho điểm vượt quá 1.0.
            new_score: float = min(1.0, old_score + self.recovery_step)
            self.trust_scores[ip_address] = new_score

    def get_all_trust_scores(self) -> Dict[str, float]:
        with self.lock:
            # Trả về bản sao để mã bên ngoài không sửa trực tiếp dữ liệu nội bộ.
            return dict(self.trust_scores)

    def explain_decision(self, ip_address: str) -> Dict[str, Any]:
        # Đọc score và số penalty trong cùng vùng khóa để báo cáo nhất quán.
        with self.lock:
            score: float = self.trust_scores.get(ip_address, 1.0)
            penalties: int = self.penalties_count.get(ip_address, 0)
            
        # Gọi lại cùng hàm ra quyết định được controller sử dụng, tránh sai khác
        # giữa phần giải thích và hành động thực tế.
        action: str = self.get_mitigation_action(ip_address)

        # Tạo lý do dạng văn bản để phục vụ log, API hoặc giao diện giải thích quyết định.
        if action == "HARD_ISOLATION":
            reason: str = f"Điểm tin cậy ({score:.2f}) dưới ngưỡng cách ly (0.40)."
        elif action == "ADAPTIVE_MICROSEGMENTATION":
            reason = f"Điểm tin cậy ({score:.2f}) dưới ngưỡng an toàn (0.85), áp dụng vi phân đoạn thích ứng."
        else:
            reason = f"Điểm tin cậy ({score:.2f}) nằm trong vùng an toàn."

        # last_updated là thời điểm tạo bản giải thích, không phải thời điểm score đổi gần nhất.
        return {
            'action': action,
            'trust_score': score,
            'last_updated': datetime.datetime.now().isoformat(),
            'penalties_applied': penalties,
            'reason': reason
        }
