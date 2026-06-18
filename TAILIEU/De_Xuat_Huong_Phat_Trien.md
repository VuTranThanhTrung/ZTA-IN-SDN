# Đề xuất các Hướng Phát triển tiếp theo cho Khóa luận tốt nghiệp
> [!TIP]
> Dựa trên việc phân tích các khoảng trống nghiên cứu (Research Gaps) từ 2 bài báo bạn cung cấp và hiện trạng mã nguồn hiện tại của bạn, dưới đây là 5 hướng đi đột phá giúp nâng tầm học thuật và tính thực tiễn cho khóa luận của bạn.

---

## 1. Tối ưu hóa hiệu năng: Chuyển đổi từ Disk I/O sang In-Memory Queue
* **Hạn chế hiện tại:** Bộ điều khiển Ryu (`ZTA_controller.py`) ghi dữ liệu luồng vào file CSV tạm thời `PredictFlowStatsfile.csv`, sau đó tiến trình giám sát đọc lại file này bằng thư viện Pandas để dự đoán mỗi 2 giây. Cơ chế ghi/đọc file liên tục lên ổ đĩa cứng (Disk I/O) là một điểm nghẽn cổ chai (Bottleneck) lớn về hiệu năng, có thể gây treo hệ thống khi xảy ra tấn công DDoS cường độ cao.
* **Đề xuất thực hiện:** 
  * Thay thế file CSV bằng cấu trúc dữ liệu hàng đợi lưu trữ hoàn toàn trên RAM (**In-Memory Queue** như `queue.Queue` trong Python hoặc cơ chế luồng dùng `deque` có kích thước giới hạn).
  * Việc này sẽ loại bỏ hoàn toàn độ trễ đọc/ghi ổ đĩa, giảm thời gian phản hồi (Response Latency) từ mức giây xuống mức **mili-giây** (ms), tăng tính thực thời (Real-time) cho hệ thống ZTA.

---

## 2. Xây dựng Điểm tin cậy động (Dynamic Trust Score)
* **Hạn chế hiện tại:** Quyết định xử lý của bạn hiện đang mang tính phân lớp cứng dựa vào nhãn ML (ví dụ: hễ đoán là DDoS thì cách ly cứng lập tức).
* **Đề xuất thực hiện:** Hiện thực hóa khái niệm **Đánh giá độ tin cậy liên tục** của Zero Trust bằng cách gán cho mỗi IP nguồn một điểm số tin cậy động $T(t) \in [0.0, 1.0]$:
  * **Trạng thái ban đầu:** Mọi thiết bị mới kết nối bắt đầu với $T(0) = 1.0$ (hoặc điểm trung bình $0.5$ để bắt đầu xác thực).
  * **Trừ điểm (Trust Decay):** Mỗi khi mô hình ML phát hiện một luồng bất thường, điểm tin cậy của IP đó sẽ bị giảm đi một lượng tỷ lệ thuận với xác suất dự đoán (Prediction Probability) và độ nghiêm trọng của lớp tấn công.
  * **Cấp quyền truy cập phân lớp:**
    * $0.8 \le T(t) \le 1.0$: Quyền truy cập đầy đủ (Normal).
    * $0.4 \le T(t) < 0.8$: Giới hạn băng thông (Rate-limiting qua Meter Table).
    * $T(t) < 0.4$: Cô lập hoàn toàn (Hard Isolation).
  * **Phục hồi điểm tin cậy (Trust Recovery):** Điểm tin cậy sẽ tăng dần trở lại một cách chậm rãi nếu thiết bị chỉ gửi lưu lượng benign (hợp lệ) trong một khoảng thời gian dài tiếp theo.

---

## 3. Tích hợp Trí tuệ nhân tạo có thể giải thích (Explainable AI - XAI)
* **Hạn chế hiện tại:** Mô hình Random Forest là một mô hình dạng "hộp đen" (Black-box). Người quản trị hệ thống chỉ biết thiết bị bị chặn vì bị gán nhãn "DDoS" hoặc "Web Attack" mà không rõ cụ thể thuộc tính mạng nào đã dẫn đến quyết định đó.
* **Đề xuất thực hiện:**
  * Sử dụng các thư viện giải thích mô hình gọn nhẹ (hoặc trích xuất thuộc tính quan trọng - Feature Importance trực tiếp từ thuật toán Random Forest).
  * Khi đưa ra quyết định xử phạt, controller sẽ in ra log (hoặc ghi vào file báo cáo) lý do giải thích bằng ngôn ngữ tự nhiên: 
    > *"IP 10.0.0.3 bị bóp băng thông vì chỉ số `packet_count_per_second` tăng vọt gấp 3 lần bình thường và số lượng cổng đích truy cập độc bản (`unique_dst_ports_src`) tăng đột biến."*
  * Điều này đáp ứng chính xác xu hướng nghiên cứu mới nhất về tính minh bạch và khả năng kiểm toán (Auditability) trong an ninh mạng.

---

## 4. Đánh giá tính bền vững trước Tấn công né tránh AI (Adversarial ML Robustness)
* **Hạn chế hiện tại:** Mã nguồn hiện tại giả định rằng kẻ tấn công gửi traffic tự nhiên. Trong thực tế, kẻ tấn công tinh vi có thể điều chỉnh tốc độ hoặc kích thước gói tin (chèn nhiễu) để đánh lừa mô hình ML (Evasion Attack).
* **Đề xuất thực hiện:**
  * Tạo kịch bản kiểm thử nơi traffic tấn công DDoS được gửi ngắt quãng hoặc giảm tốc độ (thay đổi các đặc trưng như `packet_count_per_second` hay `byte_count_per_second`) để xem mô hình Random Forest có bị vượt qua hay không.
  * Đề xuất giải pháp tăng cường tính vững chắc (Robustness) bằng cách huấn luyện đối kháng (**Adversarial Training**) hoặc loại bỏ các đặc trưng dễ bị thao túng bởi kẻ tấn công.

---

## 5. Đo lường hiệu năng thực nghiệm (System Benchmarking & Overhead Evaluation)
* **Đề xuất thực hiện:** Để phần thực nghiệm trong khóa luận thuyết phục hơn, bạn nên đo đạc và vẽ biểu đồ so sánh:
  * **Độ trễ trung bình của gói tin (Packet Latency)** khi đi qua Switch trong 3 trường hợp: (1) Mạng bình thường, (2) Mạng bị tấn công không có ZTA, (3) Mạng bị tấn công có ZTA can thiệp.
  * **Mức tiêu thụ CPU/RAM** của bộ điều khiển Ryu khi chạy ZTA enforcer để chứng minh giải pháp của bạn không gây nghẽn và thực sự khả thi khi triển khai thực tế.
