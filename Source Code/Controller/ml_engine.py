import os
from typing import Tuple, Any
import numpy as np
import pandas as pd
import joblib

DEFAULT_MODEL_FILENAME = "rf_model_multiclass_group_safe.pkl"

class MLDetectionEngine:
    """
    MLDetectionEngine loads a pre-trained Random Forest model
    and performs real-time traffic classification.
    """
    def __init__(self, model_path: str, logger: Any = None) -> None:
        """
        Initialize the ML Detection Engine.

        :param model_path: Path to the serialized ML model file.
        :param logger: Optional logger instance for recording operational logs.
        """
        self.model_path: str = model_path
        self.logger: Any = logger
        self.model: Any = None
        self.model_loaded: bool = False
        self.load_model()

    def load_model(self) -> bool:
        """
        Load the pre-trained Random Forest model.

        :return: True if the model is loaded successfully, False otherwise.
        """
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
        """
        Perform flow prediction using the loaded model.

        :param flows_df: DataFrame containing the flow records.
        :return: A tuple of numpy arrays (predictions, probabilities).
        """
        if not self.model_loaded:
            self.load_model()
            if not self.model_loaded:
                if self.logger:
                    self.logger.error("[!] Mô hình chưa được nạp. Không thể thực hiện dự đoán.")
                return np.array([]), np.array([])

        if flows_df.empty:
            return np.array([]), np.array([])

        # Ensure features align exactly with training feature space
        features_df = flows_df.copy()
        if hasattr(self.model, "feature_names_in_"):
            try:
                features_df = features_df[self.model.feature_names_in_]
            except KeyError as e:
                if self.logger:
                    self.logger.error("[!] Thiếu các thuộc tính đặc trưng mong đợi để dự đoán: %s", str(e))
                return np.array([]), np.array([])

        batch_size: int = len(features_df)

        try:
            predictions: np.ndarray = self.model.predict(features_df)
            probabilities: np.ndarray = self.model.predict_proba(features_df)
            return predictions, probabilities
        except Exception as e:
            if self.logger:
                self.logger.error("[!] Quá trình dự đoán thất bại: %s", str(e))
            return np.array([]), np.array([])
