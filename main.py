import os
import time
import hashlib
import socket
import threading
import requests
import uuid
import fnmatch
import tempfile
import shutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

from fastapi import FastAPI, UploadFile, File, Request
import uvicorn

FOLDER_TO_SYNC = Path(__file__).parent.resolve() / "sync"
SINKIGNORE_FILE = FOLDER_TO_SYNC / ".sinkignore"
PEER_PORT = 9001
SERVICE_TYPE = "_sink._tcp.local."

unique_id = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-peer-{unique_id}._sink._tcp.local."
DEVICE_ID = unique_id

file_hash_cache = {}
sinkignore_patterns = []

file_hash_lock = threading.Lock()
ignore_deletes_lock = threading.Lock()

observer = None
event_handler = None

def load_sinkignore():
    global sinkignore_patterns
    if SINKIGNORE_FILE.exists():
        with open(SINKIGNORE_FILE, "r") as f:
            sinkignore_patterns = [line.strip() for line in f if line.strip() and not line.startswith("#")]

def is_ignored(filepath):
    rel_path = str(filepath.relative_to(FOLDER_TO_SYNC)).replace("\\", "/")
    for pattern in sinkignore_patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
    return False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def hash_file(filepath):
    if not filepath.is_file() or filepath.is_symlink():
        return None
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

class SyncHandler(FileSystemEventHandler):
    def __init__(self, peer_ips):
        self.peer_ips = peer_ips
        self.ignore_deletes = set()
        self.recent_sizes = {}
        self.recent_size_lock = threading.Lock()

    def _wait_for_stable_file(self, file_path, timeout=2.0, poll=0.2):
        if not file_path.is_file() or file_path.is_symlink():
            return False
        start = time.time()
        last_size = -1
        while time.time() - start < timeout:
            size = file_path.stat().st_size
            if size == last_size:
                return True
            last_size = size
            time.sleep(poll)
        return file_path.stat().st_size == last_size

    def on_modified(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if not file_path.is_file() or file_path.is_symlink():
            return

        if is_ignored(file_path):
            return

        if not self._wait_for_stable_file(file_path):
            print(f"file not stable: {file_path}")
            return

        rel_path = str(file_path.relative_to(FOLDER_TO_SYNC)).replace("\\", "/")
        new_hash = hash_file(file_path)
        if new_hash is None:
            return

        with file_hash_lock:
            if rel_path in file_hash_cache and file_hash_cache[rel_path] == new_hash:
                return
            file_hash_cache[rel_path] = new_hash

        print(f"sending {file_path} to peers")
        for peer_ip in self.peer_ips.copy():
            try:
                files = {'file': (rel_path, open(file_path, 'rb'))}
                r = requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", files=files, timeout=5)
                if r.ok:
                    resp = r.json()
                    if resp.get("hash") != new_hash:
                        print(f"hash mismatch after sync for {rel_path} with {peer_ip}")
            except Exception as e:
                print(f"failed to sync file: {e}")

    def on_moved(self, event):
        if event.is_directory:
            return
        src_path = Path(event.src_path)
        dest_path = Path(event.dest_path)
        if is_ignored(src_path) and is_ignored(dest_path):
            return

        print(f"renamed: {src_path} -> {dest_path}")
        self.on_deleted(event)
        self.on_modified(event)

    def on_deleted(self, event):
        if event.is_directory:
            root = Path(event.src_path)
            for file in root.rglob("*"):
                if file.is_file() and not is_ignored(file):
                    self._delete_file_on_peers(file)
            return
        file_path = Path(event.src_path)
        if is_ignored(file_path):
            return
        rel_path = str(file_path.relative_to(FOLDER_TO_SYNC)).replace("\\", "/")
        with ignore_deletes_lock:
            if rel_path in self.ignore_deletes:
                self.ignore_deletes.remove(rel_path)
                return
        self._delete_file_on_peers(file_path)

    def _delete_file_on_peers(self, file_path):
        rel_path = str(file_path.relative_to(FOLDER_TO_SYNC)).replace("\\", "/")
        print(f"deleting {rel_path} on peers")
        for peer_ip in self.peer_ips.copy():
            try:
                requests.post(
                    f"http://{peer_ip}:{PEER_PORT}/delete",
                    json={"filename": rel_path, "origin": DEVICE_ID},
                    timeout=5
                )
            except Exception as e:
                print(f"failed to notify peer about deletion: {e}")

app = FastAPI()

@app.post("/sync")
async def sync_file(file: UploadFile = File(...)):
    try:
        rel_path = Path(file.filename)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            print(f"rejected path traversal: {file.filename}")
            return {"status": "error", "message": "Invalid filename/path"}

        path = FOLDER_TO_SYNC / rel_path
        if is_ignored(path):
            print(f"ignored: {file.filename}")
            return {"status": "ignored"}

        path.parent.mkdir(parents=True, exist_ok=True)
        contents = await file.read()

        with tempfile.NamedTemporaryFile(delete=False, dir=str(path.parent)) as tmp:
            tmp.write(contents)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)

        shutil.move(str(tmp_path), path)
        file_hash = hashlib.sha256(contents).hexdigest()
        with file_hash_lock:
            file_hash_cache[str(rel_path)] = file_hash
        print(f"received: {rel_path} -> wrote to {path.resolve()} ({len(contents)} bytes)")
        return {"status": "ok", "hash": file_hash}
    except Exception as e:
        print(f"error during file sync: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/delete")
async def delete_file(request: Request):
    try:
        data = await request.json()
        filename = data.get("filename")
        origin = data.get("origin")

        if origin == DEVICE_ID:
            print(f"skipping deletion of {filename} (originated from self)")
            return {"status": "skipped"}

        if not filename:
            return {"status": "error", "message": "No filename provided"}

        path = FOLDER_TO_SYNC / filename
        try:
            if path.exists():
                path.unlink()
                with file_hash_lock:
                    file_hash_cache.pop(filename, None)
                print(f"deleted: {filename}")
                if observer and event_handler:
                    with ignore_deletes_lock:
                        event_handler.ignore_deletes.add(filename)
                return {"status": "deleted"}
            else:
                return {"status": "not_found"}
        except Exception as e:
            print(f"error deleting file: {e}")
            return {"status": "error", "message": f"Failed to delete {filename}: {e}"}
    except Exception as e:
        print(f"error handling delete request: {e}")
        return {"status": "error", "message": str(e)}

def sync_all_files_to_peer(peer_ip):
    print(f"performing initial sync to peer {peer_ip}")
    for filepath in FOLDER_TO_SYNC.rglob("*"):
        if not filepath.is_file() or filepath.is_symlink():
            continue
        if is_ignored(filepath):
            continue
        rel_path = str(filepath.relative_to(FOLDER_TO_SYNC)).replace("\\", "/")
        local_hash = hash_file(filepath)
        with file_hash_lock:
            cached_hash = file_hash_cache.get(rel_path)
            if cached_hash == local_hash:
                continue
            file_hash_cache[rel_path] = local_hash
        print(f"sending {filepath} to peer during initial sync")
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (rel_path, f)}
                requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", files=files, timeout=5)
        except Exception as e:
            print(f"failed to sync file {rel_path}: {e}")

class SinkPeerListener:
    def __init__(self, local_ip):
        self.peer_ips = set()
        self.local_ip = local_ip

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip == self.local_ip:
                return
            if ip not in self.peer_ips:
                self.peer_ips.add(ip)
                print(f"found peer: {ip}")
                threading.Thread(target=sync_all_files_to_peer, args=(ip,), daemon=True).start()

    def remove_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip in self.peer_ips:
                print(f"peer {ip} removed")
                self.peer_ips.remove(ip)
                print("waiting for peer...")

    def update_service(self, zeroconf, type, name):
        pass

if __name__ == "__main__":
    FOLDER_TO_SYNC.mkdir(exist_ok=True)
    load_sinkignore()

    local_ip = get_local_ip()
    zeroconf = Zeroconf()

    desc = {}
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(local_ip)],
        port=PEER_PORT,
        properties=desc,
        server=socket.gethostname() + ".local."
    )

    print("registering service")
    zeroconf.register_service(info)

    listener = SinkPeerListener(local_ip)
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    def run_api():
        uvicorn.run(app, host="0.0.0.0", port=PEER_PORT, log_level="warning")

    threading.Thread(target=run_api, daemon=True).start()

    print("waiting for peer...")
    while not listener.peer_ips:
        time.sleep(1)

    print("watching for changes")
    event_handler = SyncHandler(listener.peer_ips)
    observer = Observer()
    observer.schedule(event_handler, str(FOLDER_TO_SYNC), recursive=True)
    observer.start()

    try:
        while True:
            if not listener.peer_ips:
                observer.stop()
                observer.join()
                print("peer lost, waiting for reconnection...")
                while not listener.peer_ips:
                    time.sleep(1)
                event_handler = SyncHandler(listener.peer_ips)
                observer = Observer()
                observer.schedule(event_handler, str(FOLDER_TO_SYNC), recursive=True)
                observer.start()
                print(f"peer(s) reconnected: {listener.peer_ips}")
            else:
                event_handler.peer_ips = listener.peer_ips.copy()
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        zeroconf.unregister_service(info)
        zeroconf.close()
        observer.join()