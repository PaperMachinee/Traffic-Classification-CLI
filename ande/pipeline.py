from __future__ import annotations

import pickle
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional, Union

import numpy as np
from rich.progress import track

ProgressCallback = Callable[[str, str, Optional[float]], None]


class PipelineError(RuntimeError):
    """Domain error for preprocessing/classification failures."""


def _notify(progress: Optional[ProgressCallback], stage: str, message: str, ratio: Optional[float] = None) -> None:
    if progress is not None:
        progress(stage, message, ratio)


def _ensure_dependency(command: str, help_text: str) -> None:
    if shutil.which(command) is None:
        raise PipelineError(f"Missing dependency `{command}`. {help_text}")


def _iter_files_with_suffix(folder: Path, suffix: str) -> list[Path]:
    return [p for p in sorted(folder.iterdir()) if p.is_file() and p.suffix.lower() == suffix.lower()]


def preprocess_traffic(
    pcap_path: Union[str, Path] = "./pcap",
    *,
    sessions_dir: Union[str, Path] = "./sessions",
    npy_dir: Union[str, Path] = "./npy",
    statistic_json_path: Union[str, Path] = "./statistic_features.json",
    trim_size: int = 8100,
    cleanup_sessions: bool = True,
    progress: Optional[ProgressCallback] = None,
) -> dict[str, Any]:
    """Preprocess pcap/pcapng files into npy feature files."""

    try:
        from pcap_splitter.splitter import PcapSplitter
    except Exception as exc:  # pragma: no cover - dependency environment-specific
        raise PipelineError(
            "Failed to import `pcap_splitter`. Install `pcap-splitter` and system dependency PcapPlusPlus."
        ) from exc
    try:
        from utils.PcapTrim import pcap_trim
        from utils.feature2json import statisticFeature2JSON
        from utils.pcap2npy import save_pcap2npy
        from utils.sessionanonymize import anonymize
    except Exception as exc:  # pragma: no cover - dependency environment-specific
        raise PipelineError(
            "Failed to import preprocessing dependencies (likely scapy-related). Install project requirements first."
        ) from exc

    pcap_path = Path(pcap_path)
    sessions_dir = Path(sessions_dir)
    npy_dir = Path(npy_dir)
    statistic_json_path = Path(statistic_json_path)

    if not pcap_path.exists() or not pcap_path.is_dir():
        raise PipelineError(f"Input pcap directory not found: {pcap_path}")

    sessions_dir.mkdir(parents=True, exist_ok=True)
    npy_dir.mkdir(parents=True, exist_ok=True)
    statistic_json_path.parent.mkdir(parents=True, exist_ok=True)

    _notify(progress, "preprocess", f"Scanning input directory: {pcap_path}", 0.0)

    pcapng_files = _iter_files_with_suffix(pcap_path, ".pcapng")
    if pcapng_files:
        _ensure_dependency("editcap", "Install Wireshark CLI tools (editcap) before preprocessing.")
    for idx, src in enumerate(pcapng_files, start=1):
        dst = src.with_suffix(".pcap")
        _notify(progress, "convert", f"Converting {src.name} -> {dst.name}", idx / max(len(pcapng_files), 1))
        command = ["editcap", "-F", "pcap", str(src), str(dst)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise PipelineError(f"editcap failed for {src.name}: {result.stderr.strip()}")

    pcap_files = _iter_files_with_suffix(pcap_path, ".pcap")
    if not pcap_files:
        raise PipelineError(f"No .pcap/.pcapng files found under {pcap_path}")

    _notify(progress, "split", f"Splitting {len(pcap_files)} pcap file(s) into sessions", 0.2)
    for src in track(pcap_files, description="splitting..."):
        ps = PcapSplitter(str(src))
        ps.split_by_session(str(sessions_dir))

    _notify(progress, "features", "Extracting statistic features", 0.45)
    statisticFeature2JSON(str(sessions_dir), output_json_path=str(statistic_json_path))

    _notify(progress, "anonymize", "Anonymizing sessions", 0.6)
    anonymize(str(sessions_dir))

    _notify(progress, "trim", f"Trimming session pcaps to {trim_size} bytes", 0.75)
    pcap_trim(str(sessions_dir), trim_size)

    if not _iter_files_with_suffix(sessions_dir, ".pcap"):
        raise PipelineError("No valid sessions were generated after preprocessing")

    _notify(progress, "npy", "Saving npy files", 0.9)
    save_pcap2npy(str(sessions_dir), str(statistic_json_path), npy_output_dir=str(npy_dir))

    deleted = 0
    if cleanup_sessions:
        _notify(progress, "cleanup", "Cleaning generated session pcaps", 0.95)
        for file_path in _iter_files_with_suffix(sessions_dir, ".pcap"):
            file_path.unlink(missing_ok=True)
            deleted += 1

    _notify(progress, "done", "Preprocess completed", 1.0)
    return {
        "pcap_dir": str(pcap_path),
        "sessions_dir": str(sessions_dir),
        "npy_dir": str(npy_dir),
        "statistic_json_path": str(statistic_json_path),
        "trim_size": trim_size,
        "input_pcap_count": len(pcap_files),
        "input_pcapng_count": len(pcapng_files),
        "cleaned_session_files": deleted,
    }


def classify_npy(
    npy_path: Union[str, Path] = "./npy",
    *,
    classify_type: int = 2,
    model_dir: Union[str, Path] = "./model",
    progress: Optional[ProgressCallback] = None,
) -> dict[str, Any]:
    """Classify preprocessed traffic from npy files."""

    npy_path = Path(npy_path)
    model_dir = Path(model_dir)
    statistic_file = npy_path / "statistic.npy"
    pcap_file = npy_path / "pcap.npy"

    if classify_type == 2:
        if not statistic_file.exists():
            raise PipelineError(f"Required file not found: {statistic_file}")
        model_file = model_dir / "rf.pkl"
        if not model_file.exists():
            raise PipelineError(f"2-class model file not found: {model_file}")

        _notify(progress, "classify", "Loading statistic.npy and random forest model", 0.2)
        test_data = np.load(statistic_file)
        if test_data.size == 0:
            raise PipelineError("statistic.npy is empty")

        with open(model_file, "rb") as file:
            loaded_model = pickle.load(file)

        _notify(progress, "classify", "Running 2-class prediction", 0.7)
        prediction = loaded_model.predict(test_data)
        count = np.bincount(prediction).argmax()
        count2label = {"NORMAL": 0, "Tor": 1}
        label = next(key for key, value in count2label.items() if value == count)

        values, counts = np.unique(prediction, return_counts=True)
        histogram = {str(int(v)): int(c) for v, c in zip(values, counts)}
        _notify(progress, "done", "Classification completed", 1.0)
        return {
            "type": 2,
            "label": label,
            "raw_majority_index": int(count),
            "prediction_histogram": histogram,
            "samples": int(len(prediction)),
        }

    if classify_type == 14:
        try:
            import torch
            from utils.test14 import ANDE, get_tensor_data
        except Exception as exc:  # pragma: no cover - dependency environment-specific
            raise PipelineError("Failed to import PyTorch 14-class model dependencies") from exc

        if not pcap_file.exists():
            raise PipelineError(f"Required file not found: {pcap_file}")
        if not statistic_file.exists():
            raise PipelineError(f"Required file not found: {statistic_file}")
        model_file = model_dir / "8100_session_mymodel.pth"
        if not model_file.exists():
            raise PipelineError(f"14-class model file not found: {model_file}")

        _notify(progress, "classify", "Loading npy tensors", 0.1)
        pcap_data, statistic_data = get_tensor_data(pcap_file=str(pcap_file), statistic_file=str(statistic_file))
        if pcap_data.shape[0] == 0:
            raise PipelineError("pcap.npy contains no samples")
        pcap_data = pcap_data / 255

        labelandindex = {
            "Browsing": 0,
            "Chat": 1,
            "Email": 2,
            "FT": 3,
            "P2P": 4,
            "Streaming": 5,
            "Tor_Browsing": 6,
            "Tor_Chat": 7,
            "Tor_Email": 8,
            "Tor_FT": 9,
            "Tor_P2P": 10,
            "Tor_Streaming": 11,
            "Tor_VoIP": 12,
            "VoIP": 13,
        }
        index2label = {j: i for i, j in labelandindex.items()}

        _notify(progress, "classify", "Loading 14-class PyTorch model", 0.2)
        model = ANDE(str(model_file), pretrained=True, num_classes=14).to("cpu")

        _notify(progress, "classify", "Running 14-class prediction", 0.3)
        start_index = 0
        y_pred_all = None
        total = pcap_data.shape[0]
        for i in track(list(range(1, total + 1)), description="Validation..."):
            y_pred, _ = model(pcap_data[start_index:i], statistic_data[start_index:i])
            start_index = i
            if y_pred_all is None:
                y_pred_all = y_pred.cpu().detach()
            else:
                y_pred_all = torch.cat((y_pred_all, y_pred.cpu().detach()), dim=0)
            if i % max(total // 10, 1) == 0:
                _notify(progress, "classify", f"Predicted {i}/{total} samples", 0.3 + 0.6 * (i / total))

        if y_pred_all is None:
            raise PipelineError("Model did not produce predictions")

        _, pred = y_pred_all.topk(1, 1, largest=True, sorted=True)
        pred_label = [index2label.get(i.tolist()) for i in pred.view(-1).cpu().detach()]
        unique_strings, counts = np.unique(pred_label, return_counts=True)
        most_common_string = unique_strings[np.argmax(counts)]

        _notify(progress, "done", "Classification completed", 1.0)
        return {
            "type": 14,
            "label": most_common_string,
            "prediction_histogram": {str(label): int(count) for label, count in zip(unique_strings, counts)},
            "samples": int(len(pred_label)),
        }

    raise PipelineError(f"Unsupported classification type: {classify_type}")


def run_preprocess_and_classify(
    pcap_path: Union[str, Path],
    *,
    classify_type: int = 2,
    sessions_dir: Union[str, Path],
    npy_dir: Union[str, Path],
    statistic_json_path: Union[str, Path],
    model_dir: Union[str, Path] = "./model",
    trim_size: int = 8100,
    cleanup_sessions: bool = True,
    progress: Optional[ProgressCallback] = None,
) -> dict[str, Any]:
    preprocess_info = preprocess_traffic(
        pcap_path,
        sessions_dir=sessions_dir,
        npy_dir=npy_dir,
        statistic_json_path=statistic_json_path,
        trim_size=trim_size,
        cleanup_sessions=cleanup_sessions,
        progress=progress,
    )
    result = classify_npy(
        npy_path=npy_dir,
        classify_type=classify_type,
        model_dir=model_dir,
        progress=progress,
    )
    return {"preprocess": preprocess_info, "classification": result}
