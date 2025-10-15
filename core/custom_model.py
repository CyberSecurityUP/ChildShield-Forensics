# core/custom_model.py
# Custom image model loader:
#   - python_module: path/to/module.py exposing score_image(path)->float [0..1]
#   - onnx: path/to/model.onnx (requires onnxruntime)
#
# Usage:
#   loader = ModelLoader("python_module", "my_model.py")
#   p = loader.score_image("image.jpg")  # 0..1

import importlib.util
from typing import Callable, Optional

from PIL import Image
import numpy as np

class ModelLoader:
    def __init__(self, model_type: str, model_path: str):
        self.model_type = (model_type or "").lower()
        self.model_path = model_path
        self._fn: Optional[Callable[[str], float]] = None
        self._sess = None
        self._input_name = None
        self._expects_chw = False  # simple switch if model expects CHW

        if self.model_type == "python_module":
            self._load_python_module()
        elif self.model_type == "onnx":
            self._load_onnx_model()
        else:
            raise ValueError(f"Unsupported model_type: {self.model_type}")

    # ---------- Python module ----------
    def _load_python_module(self):
        spec = importlib.util.spec_from_file_location("custom_image_model", self.model_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Failed to load python module spec")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # preferred name
        fn = getattr(mod, "score_image", None) or getattr(mod, "nsfw_score_image", None)
        if not callable(fn):
            raise RuntimeError("Module must define score_image(path)->float (0..1)")
        self._fn = fn

    # ---------- ONNX runtime ----------
    def _load_onnx_model(self):
        try:
            import onnxruntime as ort
        except Exception as e:
            raise RuntimeError("onnxruntime is required for ONNX models (pip install onnxruntime)") from e
        self._sess = ort.InferenceSession(self.model_path, providers=["CPUExecutionProvider"])
        inputs = self._sess.get_inputs()
        if not inputs:
            raise RuntimeError("ONNX model has no inputs")
        self._input_name = inputs[0].name
        # Best-effort: assume model expects NCHW float32 224x224 RGB normalized [0,1]
        # Many models accept NHWC too; we will try NCHW first, fallback to NHWC if needed.
        self._expects_chw = True

    def _preprocess(self, path: str):
        img = Image.open(path).convert("RGB").resize((224, 224))
        arr = np.asarray(img).astype("float32") / 255.0  # HWC, [0..1]
        if self._expects_chw:
            arr = np.transpose(arr, (2, 0, 1))  # CHW
        arr = np.expand_dims(arr, axis=0)  # NCHW or NHWC
        return arr

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        x = x - np.max(x, axis=-1, keepdims=True)
        e = np.exp(x)
        return e / np.sum(e, axis=-1, keepdims=True)

    def _score_onnx(self, path: str) -> float:
        inp = self._preprocess(path)
        try:
            y = self._sess.run(None, {self._input_name: inp})[0]
        except Exception:
            # try NHWC if NCHW failed
            self._expects_chw = False
            inp = self._preprocess(path)
            y = self._sess.run(None, {self._input_name: inp})[0]

        y = np.array(y)
        # If logits: softmax to probabilities
        if y.ndim >= 2 and y.shape[0] == 1 and y.shape[-1] > 1:
            p = self._softmax(y)[0]
            # heuristic: if 2 classes, assume index 1 = NSFW
            if p.shape[-1] == 2:
                return float(p[1])
            # else, take max prob as risk proxy
            return float(np.max(p))
        # If scalar or single prob tensor:
        try:
            return float(np.squeeze(y).item())
        except Exception:
            return float(np.clip(np.max(y), 0.0, 1.0))

    def score_image(self, path: str) -> float:
        if self.model_type == "python_module" and self._fn:
            val = float(self._fn(path))
            return max(0.0, min(1.0, val))
        if self.model_type == "onnx" and self._sess is not None:
            return max(0.0, min(1.0, self._score_onnx(path)))
        raise RuntimeError("Model not loaded")
