import hashlib
from pathlib import Path
import shutil
import time
import os
import socket

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def files_conflict(local_path, incoming_temp_path):
    h1 = file_hash(local_path)
    h2 = file_hash(incoming_temp_path)
    if h1 is not None and h2 is not None and h1 != h2:
        return True
    return False

def get_device_name():
    return socket.gethostname()

def handle_conflict(rel_path, local_path, incoming_temp_path, remote_device_name, sync_callback=None, sync_folder=None):
    device_name = get_device_name()
    conflict_base = Path(local_path).parent / ".sink_conflicts"
    local_conflict_dir = conflict_base / device_name
    remote_conflict_dir = conflict_base / remote_device_name

    local_conflict_dir.mkdir(parents=True, exist_ok=True)
    remote_conflict_dir.mkdir(parents=True, exist_ok=True)

    rel_filename = Path(rel_path).name
    timestamp = int(time.time())

    local_conflict_file = local_conflict_dir / f"{timestamp}.{rel_filename}"
    remote_conflict_file = remote_conflict_dir / f"{timestamp}.{rel_filename}"

    if Path(local_path).exists():
        shutil.move(str(local_path), str(local_conflict_file))
        print(f"[sink] Local conflicting file moved to {local_conflict_file}")
        if sync_callback and sync_folder:
            rel_conflict = os.path.relpath(local_conflict_file, start=sync_folder)
            sync_callback(rel_conflict, str(local_conflict_file), file_hash(local_conflict_file))

    if Path(incoming_temp_path).exists():
        shutil.move(str(incoming_temp_path), str(remote_conflict_file))
        print(f"[sink] Incoming conflicting file moved to {remote_conflict_file}")
        if sync_callback and sync_folder:
            rel_conflict = os.path.relpath(remote_conflict_file, start=sync_folder)
            sync_callback(rel_conflict, str(remote_conflict_file), file_hash(remote_conflict_file))

    print(f"[sink] Conflict detected for {rel_path}. Both versions moved to .sink_conflicts/{device_name}/ and .sink_conflicts/{remote_device_name}/")
