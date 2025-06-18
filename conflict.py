import hashlib
from pathlib import Path
import shutil
import time
import os

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

def backup_conflict_file(path, conflict_dir=".sink_conflicts"):
    p = Path(path)
    conflict_folder = p.parent / conflict_dir
    conflict_folder.mkdir(exist_ok=True)
    timestamp = int(time.time())
    new_name = f"{p.name}.conflict.{timestamp}"
    new_path = conflict_folder / new_name
    shutil.move(str(p), str(new_path))
    print(f"[sink] Backed up conflicting file as {new_path}")
    return new_path

def handle_conflict(rel_path, local_path, incoming_temp_path, sync_callback=None, sync_folder=None):
    print(f"[sink] Conflict detected for {rel_path}: backing up local and accepting incoming file.")
    backup_path = backup_conflict_file(local_path)
    if sync_callback and backup_path and sync_folder:
        rel_conflict = os.path.relpath(backup_path, start=sync_folder)
        sync_callback(rel_conflict, str(backup_path), file_hash(backup_path))