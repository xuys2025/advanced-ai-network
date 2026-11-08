"""Assemble a Windows release from checked-out sources and pinned runtimes."""
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = "AdvancedAINetwork-LAN-Windows-x64.zip"
UPSTREAM = "AdvancedAINetwork-ThirdParty-Sources.zip"
PREFIX = WINDOWS[:-4] + "/"
RUNTIME_DIGEST = "68fcb68d8d4a52bc0286749507bea298c91ae0159d87f0c7162296c60f9236a3"
SOURCE_DIGEST = "e23faf531ef759400dcbcd793e35c42dc94ecded5afbeb7537e3cdeccf833f74"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(base, stage):
    if digest(base / WINDOWS) != RUNTIME_DIGEST or digest(base / UPSTREAM) != SOURCE_DIGEST:
        raise ValueError("Unexpected baseline archive digest")
    stage.mkdir(parents=True)
    with ZipFile(base / WINDOWS) as archive:
        for entry in archive.infolist():
            name = entry.filename.removeprefix(PREFIX)
            if entry.is_dir() or not entry.filename.startswith(PREFIX):
                continue
            runtime = name.startswith("App/") and not name.startswith("App/resources/") and name != "App/AdvancedAINetworkLauncher.exe"
            if runtime or name in ("Guard/core/sing-box.exe", "Guard/core/COPYING", "Guard/core/LICENSE", "Gateway/ProxyBridgeCore.dll"):
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    for raw in filter(None, tracked):
        name = os.fsdecode(raw)
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    for folder in ("Tools", "App/resources/native", "App/resources/app"):
        (stage / folder).mkdir(parents=True, exist_ok=True)


def pack(base, stage, output):
    import shutil
    output.mkdir(parents=True)
    files = sorted(p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file())
    manifest = {name: digest(stage / name) for name in files}
    sums = "SHA256SUMS.txt"
    (stage / sums).write_bytes("".join(f"{value}  {name}\n" for name, value in manifest.items()).encode())
    manifest[sums] = digest(stage / sums)
    with ZipFile(output / WINDOWS, "w", ZIP_DEFLATED, compresslevel=6) as archive:
        for name in manifest:
            archive.write(stage / name, PREFIX + name)
    with ZipFile(output / WINDOWS) as archive:
        for name, expected in manifest.items():
            with archive.open(PREFIX + name) as entry:
                if hashlib.file_digest(entry, "sha256").hexdigest() != expected:
                    raise ValueError("Archive entry mismatch: " + name)
    shutil.copyfile(base / UPSTREAM, output / UPSTREAM)
    if digest(output / UPSTREAM) != SOURCE_DIGEST:
        raise ValueError("Corresponding sources changed")
    (output / sums).write_bytes("".join(f"{digest(output / name)}  {name}\n" for name in (WINDOWS, UPSTREAM)).encode())
    print(f"Verified {len(manifest)} files in the Windows ZIP.")


if __name__ == "__main__":
    operation, *paths = sys.argv[1:]
    {"prepare": prepare, "pack": pack}[operation](*map(Path, paths))
