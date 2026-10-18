#!/usr/bin/env python3
"""Behavioral tests for deterministic release archives."""

from __future__ import annotations

import os
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PACKAGER = ROOT / "scripts" / "package-release-archive.py"
EPOCH = 1_700_000_001
PAYLOAD = b"tracedecay release binary\n"
WORKER_PAYLOAD = b"tracedecay NCM worker\n"
MANIFEST_PAYLOAD = b'{"worker":"tracedecay-ncm-worker"}\n'
MODEL_ACQUISITION_PAYLOAD = b'{"model":"NCM encoder","acquisition":"runtime"}\n'


def package_command(
    binary: Path,
    output: Path,
    archive_format: str,
    entry_name: str,
    companions: tuple[tuple[Path, str], ...] = (),
) -> list[str]:
    command = [
        "python3",
        str(PACKAGER),
        "--binary",
        str(binary),
        "--output",
        str(output),
        "--format",
        archive_format,
        "--entry-name",
        entry_name,
        "--epoch",
        str(EPOCH),
    ]
    for source, companion_name in companions:
        command.extend(["--companion", f"{source}={companion_name}"])
    return command


def package(
    binary: Path,
    output: Path,
    archive_format: str,
    entry_name: str,
    companions: tuple[tuple[Path, str], ...] = (),
) -> None:
    subprocess.run(
        package_command(binary, output, archive_format, entry_name, companions),
        check=True,
    )


def test_tar_gz(temp: Path, binary: Path) -> None:
    first = temp / "first.tar.gz"
    second = temp / "second.tar.gz"
    package(binary, first, "tar.gz", "tracedecay")
    os.utime(binary, (EPOCH + 100, EPOCH + 100))
    package(binary, second, "tar.gz", "tracedecay")
    assert first.read_bytes() == second.read_bytes()

    with tarfile.open(first, "r:gz") as archive:
        entries = archive.getmembers()
        assert len(entries) == 1
        entry = entries[0]
        assert entry.name == "tracedecay"
        assert entry.mode == 0o755
        assert entry.uid == 0 and entry.gid == 0
        assert entry.uname == "" and entry.gname == ""
        assert entry.mtime == EPOCH
        extracted = archive.extractfile(entry)
        assert extracted is not None and extracted.read() == PAYLOAD


def test_zip(temp: Path, binary: Path) -> None:
    first = temp / "first.zip"
    second = temp / "second.zip"
    package(binary, first, "zip", "tracedecay.exe")
    os.utime(binary, (EPOCH + 200, EPOCH + 200))
    package(binary, second, "zip", "tracedecay.exe")
    assert first.read_bytes() == second.read_bytes()

    with zipfile.ZipFile(first) as archive:
        entries = archive.infolist()
        assert len(entries) == 1
        entry = entries[0]
        expected_time = list(time.gmtime(EPOCH)[:6])
        expected_time[5] -= expected_time[5] % 2
        assert entry.filename == "tracedecay.exe"
        assert entry.date_time == tuple(expected_time)
        assert entry.compress_type == zipfile.ZIP_STORED
        assert stat.S_IMODE(entry.external_attr >> 16) == 0o755
        assert archive.read(entry) == PAYLOAD


def test_companions(temp: Path) -> None:
    worker = temp / "worker"
    manifest = temp / "manifest.json"
    model_acquisition = temp / "model-acquisition.json"
    sources = (
        (worker, WORKER_PAYLOAD),
        (manifest, MANIFEST_PAYLOAD),
        (model_acquisition, MODEL_ACQUISITION_PAYLOAD),
    )
    for source, payload in sources:
        source.write_bytes(payload)
        source.chmod(0o700)
    companions = (
        (manifest, "worker-manifest.json"),
        (model_acquisition, "model-acquisition.json"),
    )
    expected_entries = (
        ("tracedecay-ncm-worker", WORKER_PAYLOAD, 0o755),
        ("worker-manifest.json", MANIFEST_PAYLOAD, 0o644),
        ("model-acquisition.json", MODEL_ACQUISITION_PAYLOAD, 0o644),
    )

    for archive_format in ("tar.gz", "zip"):
        first = temp / f"worker-first.{archive_format}"
        second = temp / f"worker-second.{archive_format}"
        for source, _ in sources:
            os.utime(source, (EPOCH + 100, EPOCH + 100))
            source.chmod(0o700)
        package(worker, first, archive_format, "tracedecay-ncm-worker", companions)
        for source, _ in sources:
            os.utime(source, (EPOCH + 300, EPOCH + 300))
            source.chmod(0o600)
        package(worker, second, archive_format, "tracedecay-ncm-worker", companions)
        assert first.read_bytes() == second.read_bytes()

        if archive_format == "tar.gz":
            with tarfile.open(first, "r:gz") as archive:
                entries = archive.getmembers()
                assert [entry.name for entry in entries] == [
                    name for name, _, _ in expected_entries
                ]
                for entry, (_, payload, mode) in zip(entries, expected_entries):
                    assert entry.isfile()
                    assert entry.mode == mode
                    assert entry.uid == 0 and entry.gid == 0
                    assert entry.uname == "" and entry.gname == ""
                    assert entry.mtime == EPOCH
                    extracted = archive.extractfile(entry)
                    assert extracted is not None and extracted.read() == payload
        else:
            with zipfile.ZipFile(first) as archive:
                entries = archive.infolist()
                assert [entry.filename for entry in entries] == [
                    name for name, _, _ in expected_entries
                ]
                expected_time = list(time.gmtime(EPOCH)[:6])
                expected_time[5] -= expected_time[5] % 2
                for entry, (_, payload, mode) in zip(entries, expected_entries):
                    assert stat.S_ISREG(entry.external_attr >> 16)
                    assert stat.S_IMODE(entry.external_attr >> 16) == mode
                    assert entry.date_time == tuple(expected_time)
                    assert entry.compress_type == zipfile.ZIP_STORED
                    assert archive.read(entry) == payload


def reject_package(
    temp: Path,
    case: str,
    binary: Path,
    archive_format: str,
    entry_name: str,
    companions: tuple[tuple[Path, str], ...] = (),
) -> None:
    output = temp / f"rejected-{archive_format}-{case}" / "archive"
    result = subprocess.run(
        package_command(binary, output, archive_format, entry_name, companions),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode != 0, f"accepted invalid release inputs: {case}"
    assert not output.exists(), f"created an archive for invalid inputs: {case}"
    assert not output.parent.exists(), f"created an output directory: {case}"


def test_rejected_inputs(temp: Path, binary: Path) -> None:
    companion = temp / "valid-companion"
    companion.write_bytes(MANIFEST_PAYLOAD)
    another = temp / "another-companion"
    another.write_bytes(MODEL_ACQUISITION_PAYLOAD)
    empty = temp / "empty-companion"
    empty.touch()
    directory = temp / "directory-input"
    directory.mkdir()
    symlink = temp / "symlink-input"
    symlink.symlink_to(binary)
    invalid_names = (
        "",
        ".",
        "..",
        "/absolute",
        "../escape",
        "nested/name",
        "nested\\name",
    )
    nonregular_sources = [("directory", directory)]
    if hasattr(os, "mkfifo"):
        fifo = temp / "fifo-input"
        os.mkfifo(fifo)
        nonregular_sources.append(("fifo", fifo))

    for archive_format in ("tar.gz", "zip"):
        for index, name in enumerate(invalid_names):
            reject_package(temp, f"primary-name-{index}", binary, archive_format, name)
            reject_package(
                temp,
                f"companion-name-{index}",
                binary,
                archive_format,
                "tracedecay",
                ((companion, name),),
            )
        reject_package(
            temp,
            "primary-collision",
            binary,
            archive_format,
            "tracedecay",
            ((companion, "tracedecay"),),
        )
        reject_package(
            temp,
            "companion-collision",
            binary,
            archive_format,
            "tracedecay",
            ((companion, "manifest.json"), (another, "manifest.json")),
        )
        for case, source in (
            ("missing", temp / "missing-input"),
            ("empty", empty),
            ("symlink", symlink),
            *nonregular_sources,
        ):
            reject_package(temp, f"primary-{case}", source, archive_format, "tracedecay")
            reject_package(
                temp,
                f"companion-{case}",
                binary,
                archive_format,
                "tracedecay",
                ((companion, "manifest.json"), (source, "model-acquisition.json")),
            )


def main() -> None:
    with tempfile.TemporaryDirectory(dir=os.environ.get("OWNED_TEMP_DIR")) as temp_name:
        temp = Path(temp_name)
        binary = temp / "binary"
        binary.write_bytes(PAYLOAD)
        binary.chmod(0o755)
        test_tar_gz(temp, binary)
        test_zip(temp, binary)
        test_companions(temp)
        test_rejected_inputs(temp, binary)
    print("release archive packaging tests passed")


if __name__ == "__main__":
    main()
