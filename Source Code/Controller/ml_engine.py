import os
from typing import Tuple, Any
import numpy as np
import pandas as pd
import joblib

# Tên mặc định của mô hình Random Forest đã được huấn luyện và lưu bằng joblib.
DEFAULT_MODEL_FILENAME = "random_forest_multiclass_zta.pkl"

class MLDetectionEngine:
    def __init__(self, model_path: str, logger: Any = None) -> None:
        # Chỉ lưu trạng thái và gọi load_model một lần khi khởi tạo; nếu tải thất bại,
        # hàm predict vẫn có cơ chế thử tải lại ở lần dự đoán sau.
        self.model_path: str = model_path
        self.logger: Any = logger
        self.model: Any = None
        self.model_loaded: bool = False
        self.load_model()

    def load_model(self) -> bool:
        # Kiểm tra file trước khi joblib.load để phân biệt lỗi sai đường dẫn với lỗi
        # giải tuần tự hoặc mô hình không tương thích.
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.model_loaded = True
                if self.logger:
                    self.logger.info("[+] Đã nạp thành công mô hình huấn luyện từ %s", self.model_path)
                return True
            except Exception as e:
                if self.logger:
                    self.logger.error("[!] Lỗi khi nạp mô hình từ %s: %s", self.model_path, str(e))
                return False
        else:
            if self.logger:
                self.logger.warning("[!] Đường dẫn mô hình không tồn tại: %s", self.model_path)
            return False

    def predict(self, flows_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        # Nếu mô hình chưa sẵn sàng, thử nạp lại; trả mảng rỗng thay vì làm dừng
        # toàn bộ controller khi file mô hình tạm thời không khả dụng.
        if not self.model_loaded:
            self.load_model()
            if not self.model_loaded:
                if self.logger:
                    self.logger.error("[!] Mô hình chưa được nạp. Không thể thực hiện dự đoán.")
                return np.array([]), np.array([])

        # Không gọi model.predict khi chu kỳ hiện tại không có bản ghi flow.
        if flows_df.empty:
            return np.array([]), np.array([])

        # Ensure features align exactly with training feature space
        # Random Forest yêu cầu đúng tên và thứ tự đặc trưng như lúc huấn luyện.
        # feature_names_in_ được scikit-learn lưu kèm trong model để tái lập đầu vào.
        features_df = flows_df.copy()
        if hasattr(self.model, "feature_names_in_"):
            try:
                features_df = features_df[self.model.feature_names_in_]
            except KeyError as e:
                if self.logger:
                    self.logger.error("[!] Thiếu các thuộc tính đặc trưng mong đợi để dự đoán: %s", str(e))
                return np.array([]), np.array([])

        # Số bản ghi được xử lý trong một lần dự đoán theo lô.
        batch_size: int = len(features_df)

        try:
            # predict trả về nhãn lớp; predict_proba trả xác suất của tất cả lớp.
            predictions: np.ndarray = self.model.predict(features_df)
            probabilities: np.ndarray = self.model.predict_proba(features_df)
            return predictions, probabilities
        except Exception as e:
            if self.logger:
                self.logger.error("[!] Quá trình dự đoán thất bại: %s", str(e))
            return np.array([]), np.array([])
