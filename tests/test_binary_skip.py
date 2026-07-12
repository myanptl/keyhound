"""Binary files must not be scanned as text.

Reading a model file with errors="ignore" turns megabytes of weights into garbage
"lines", and entropy detection then fires on almost all of them. That noise buries
real credentials, which is the one thing this tool exists to surface.
"""

from pathlib import Path

from keyhound.scanner import is_binary, scan_directory, scan_file

REAL_KEY = 'const k = "sk-ant-api03-' + "A" * 90 + '";\n'


def test_detects_binary_by_null_bytes(tmp_path: Path) -> None:
    blob = tmp_path / "model.dat"
    blob.write_bytes(b"weights\x00\x00\x01\x02binary garbage" * 100)
    assert is_binary(blob) is True


def test_plain_text_is_not_binary(tmp_path: Path) -> None:
    src = tmp_path / "app.js"
    src.write_text(REAL_KEY)
    assert is_binary(src) is False


def test_binary_file_yields_no_findings(tmp_path: Path) -> None:
    # A binary that happens to contain key-shaped bytes is still skipped: we cannot
    # meaningfully report a line number inside a weights blob.
    blob = tmp_path / "weights.bin"
    blob.write_bytes(b"\x00\x01" + REAL_KEY.encode() + b"\x00" * 50)
    assert scan_file(blob) == []


def test_real_secret_in_text_is_STILL_found(tmp_path: Path) -> None:
    # The regression that would matter: skipping binaries must not make the scanner
    # blind to actual secrets in actual source files.
    src = tmp_path / "config.js"
    src.write_text(REAL_KEY)
    findings = scan_file(src)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "sk-ant-api03-" + "A" * 90 not in findings[0].value  # must be redacted


def test_model_extension_skipped_without_reading(tmp_path: Path) -> None:
    model = tmp_path / "gesture_recognizer.task"
    model.write_bytes(b"\x00\x01\x02" * 500)
    assert scan_file(model) == []


def test_directory_scan_skips_binaries_but_keeps_source(tmp_path: Path) -> None:
    (tmp_path / "secret.js").write_text(REAL_KEY)
    (tmp_path / "model.task").write_bytes(b"\x00" * 4096)
    (tmp_path / "blob.bin").write_bytes(b"\x00\xff" * 4096)

    all_findings = [f for _p, fs in scan_directory(tmp_path) for f in fs]
    assert len(all_findings) == 1
    assert all_findings[0].kind
    assert all_findings[0].file.endswith("secret.js")
