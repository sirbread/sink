import os
import sys
import time
import threading
import socket
import hashlib
import shutil
import uuid
import fnmatch
import json
from pathlib import Path

import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser

SYNC_FOLDER = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "sync"
SYNC_FOLDER.mkdir(exist_ok=True)
PEER_PORT = 9191
SERVICE_TYPE = "_sinklan._tcp.local."
DEVICE_ID = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-{DEVICE_ID}._sinklan._tcp.local."

SINKIGNORE_PATH = Path(__file__).parent / ".sinkignore"
ignore_patterns = []
ignore_lock = threading.Lock()

DEVICES_FILE = Path(__file__).parent / "devices.json"

hash_cache = {}
loop_suppress = {}
known_peers = {}
peer_status = {}
trusted_by_devices = set()
peer_lock = threading.Lock()

def get_hostname():
    return socket.gethostname()

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

def relative(p):
    return str(Path(p).relative_to(SYNC_FOLDER)).replace("\\", "/")

def abs_path(rel):
    return (SYNC_FOLDER / rel).resolve()

def is_tempfile(path):
    return str(path).endswith(".sinktmp")

def is_ignored(rel_path):
    rel_path = rel_path.replace("\\", "/")
    with ignore_lock:
        patterns = list(ignore_patterns)
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
    return False

def is_conflict_file(rel_path):
    return False

def load_sinkignore():
    global ignore_patterns
    patterns = []
    if SINKIGNORE_PATH.exists():
        with open(SINKIGNORE_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    with ignore_lock:
        ignore_patterns[:] = patterns
    print(f"[sink] Loaded {len(ignore_patterns)} ignore patterns from {SINKIGNORE_PATH}")

def watch_sinkignore():
    last_mtime = SINKIGNORE_PATH.stat().st_mtime if SINKIGNORE_PATH.exists() else 0
    while True:
        try:
            current_mtime = SINKIGNORE_PATH.stat().st_mtime
            if current_mtime != last_mtime:
                print("[sink] Reloading .sinkignore...")
                load_sinkignore()
                last_mtime = current_mtime
        except FileNotFoundError:
            if last_mtime != 0:
                print("[sink] .sinkignore deleted, clearing patterns...")
                load_sinkignore()
                last_mtime = 0
        time.sleep(2)

def hash_file(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def file_hash(path):
    return hash_file(path)

def files_conflict(local_path, incoming_temp_path):
    h1 = file_hash(local_path)
    h2 = file_hash(incoming_temp_path)
    return h1 is not None and h2 is not None and h1 != h2

def handle_conflict(rel_path, local_path, incoming_temp_path, remote_device_name):
    device_name = get_hostname()
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

    if Path(incoming_temp_path).exists():
        shutil.move(str(incoming_temp_path), str(remote_conflict_file))
        print(f"[sink] Incoming conflicting file moved to {remote_conflict_file}")

    print(f"[sink] Conflict for {rel_path}. Stored in .sink_conflicts/")

def load_trusted_devices():
    if not DEVICES_FILE.exists():
        return {}
    with open(DEVICES_FILE, "r") as f:
        try:
            data = json.load(f)
            return {d["device_id"]: d for d in data.get("trusted_devices", [])}
        except Exception:
            return {}

def save_trusted_devices(devices):
    with open(DEVICES_FILE, "w") as f:
        json.dump({"trusted_devices": list(devices.values())}, f, indent=2)

def is_device_trusted(device_id):
    devices = load_trusted_devices()
    return device_id in devices

def add_trusted_device(device_id, name, ip):
    devices = load_trusted_devices()
    if device_id not in devices:
        print(f"[sink] Trusting new device: {device_id} ({name}) at {ip}")
    devices[device_id] = {"device_id": device_id, "name": name, "last_ip": ip}
    save_trusted_devices(devices)
    return True

def update_device_ip(device_id, ip):
    devices = load_trusted_devices()
    if device_id in devices:
        devices[device_id]["last_ip"] = ip
        save_trusted_devices(devices)

def sync_to_peers(rel_path, abs_path, filehash):
    if is_tempfile(rel_path) or is_ignored(rel_path):
        return
    with peer_lock:
        peers = list(known_peers.values())
    for peer in peers:
        peer_ip = peer["ip"]
        try:
            with open(abs_path, "rb") as f:
                data = f.read()
            headers = {
                "X-Sink-Meta": json.dumps({"rel_path": rel_path, "hash": filehash}),
                "X-Sink-Device-ID": DEVICE_ID,
                "X-Sink-Device-Name": get_hostname()
            }
            requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", headers=headers, data=data, timeout=5)
        except Exception:
            pass

def delete_on_peers(rel_path):
    with peer_lock:
        peers = list(known_peers.values())
    for peer in peers:
        peer_ip = peer["ip"]
        try:
            data = json.dumps({"rel_path": rel_path})
            headers = {"X-Sink-Device-ID": DEVICE_ID}
            requests.post(f"http://{peer_ip}:{PEER_PORT}/delete", headers=headers, data=data, timeout=5)
        except Exception:
            pass

def mkdir_on_peers(rel_path):
    with peer_lock:
        peers = list(known_peers.values())
    for peer in peers:
        peer_ip = peer["ip"]
        try:
            data = json.dumps({"rel_path": rel_path})
            headers = {"X-Sink-Device-ID": DEVICE_ID}
            requests.post(f"http://{peer_ip}:{PEER_PORT}/mkdir", headers=headers, data=data, timeout=5)
        except Exception:
            pass

def rmdir_on_peers(rel_path):
    with peer_lock:
        peers = list(known_peers.values())
    for peer in peers:
        peer_ip = peer["ip"]
        try:
            data = json.dumps({"rel_path": rel_path})
            headers = {"X-Sink-Device-ID": DEVICE_ID}
            requests.post(f"http://{peer_ip}:{PEER_PORT}/rmdir", headers=headers, data=data, timeout=5)
        except Exception:
            pass

class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        device_id = self.headers.get("X-Sink-Device-ID")
        remote_device_name = self.headers.get("X-Sink-Device-Name", "remote_device")
        if not device_id or not is_device_trusted(device_id):
            self.send_response(202)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        content = self.rfile.read(length)

        if self.path == "/sync":
            meta = json.loads(self.headers.get("X-Sink-Meta", "{}"))
            rel_path = meta["rel_path"]
            filehash = meta["hash"]
            dest = abs_path(rel_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".sinktmp")
            with open(tmp, "wb") as f:
                f.write(content)
            if dest.exists() and files_conflict(dest, tmp):
                handle_conflict(rel_path, dest, tmp, remote_device_name)
            else:
                shutil.move(tmp, dest)
                hash_cache[rel_path] = filehash
            self.send_response(200)
            self.end_headers()

        elif self.path == "/delete":
            meta = json.loads(content)
            rel_path = meta["rel_path"]
            path = abs_path(rel_path)
            if path.exists():
                if path.is_file():
                    path.unlink()
                else:
                    shutil.rmtree(path, ignore_errors=True)
            self.send_response(200)
            self.end_headers()

        elif self.path == "/mkdir":
            meta = json.loads(content)
            rel_path = meta["rel_path"]
            abs_path(rel_path).mkdir(parents=True, exist_ok=True)
            self.send_response(200)
            self.end_headers()

        elif self.path == "/rmdir":
            meta = json.loads(content)
            rel_path = meta["rel_path"]
            try:
                abs_path(rel_path).rmdir()
            except:
                pass
            self.send_response(200)
            self.end_headers()

    def do_GET(self):
        if self.path == "/device_id":
            data = {"device_id": DEVICE_ID, "device_name": get_hostname()}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_http_server():
    server = HTTPServer(("0.0.0.0", PEER_PORT), SinkHandler)
    print(f"[sink] Listening on port {PEER_PORT}")
    server.serve_forever()

class PeerListener:
    def __init__(self, local_ip):
        self.local_ip = local_ip

    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip == self.local_ip:
                return
            try:
                r = requests.get(f"http://{ip}:{PEER_PORT}/device_id", timeout=2)
                if r.ok:
                    data = r.json()
                    peer_id = data["device_id"]
                    peer_name = data["device_name"]
                    if peer_id == DEVICE_ID:
                        return
                    add_trusted_device(peer_id, peer_name, ip)
                    update_device_ip(peer_id, ip)
                    with peer_lock:
                        known_peers[peer_id] = {"ip": ip, "device_id": peer_id, "name": peer_name}
                    print(f"[sink] Found peer {peer_id} ({ip})")
                    snapshot = snapshot_folder()
                    for path, (typ, val) in snapshot.items():
                        if typ == "dir":
                            mkdir_on_peers(path)
                        elif typ == "file":
                            absf = abs_path(path)
                            hash_cache[path] = val
                            sync_to_peers(path, absf, val)
            except:
                pass

    def remove_service(self, *args):
        pass

    def update_service(self, *args):
        pass

def start_discovery():
    zeroconf = Zeroconf()
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(get_local_ip())],
        port=PEER_PORT,
        properties={},
        server=f"{get_hostname()}.local."
    )
    zeroconf.register_service(info)
    ServiceBrowser(zeroconf, SERVICE_TYPE, PeerListener(get_local_ip()))
    print("[sink] Zeroconf discovery started")

def snapshot_folder():
    snap = {}
    for root, dirs, files in os.walk(SYNC_FOLDER):
        for d in dirs:
            path = Path(root) / d
            rel = relative(path)
            if is_ignored(rel) or is_tempfile(rel):
                continue
            snap[rel] = ("dir", path.stat().st_mtime)
        for f in files:
            path = Path(root) / f
            rel = relative(path)
            if is_ignored(rel) or is_tempfile(rel):
                continue
            snap[rel] = ("file", hash_file(path))
    return snap

def poll_and_sync():
    previous = {}
    print("[sink] Polling every 1s")
    while True:
        current = snapshot_folder()
        added = set(current) - set(previous)
        removed = set(previous) - set(current)
        common = set(current) & set(previous)

        for path in added:
            typ, val = current[path]
            if typ == "dir":
                mkdir_on_peers(path)
            else:
                absf = abs_path(path)
                hash_cache[path] = val
                sync_to_peers(path, absf, val)

        for path in removed:
            typ, val = previous[path]
            if typ == "dir":
                rmdir_on_peers(path)
            else:
                delete_on_peers(path)
                hash_cache.pop(path, None)

        for path in common:
            typ, val = current[path]
            if typ == "file" and val != previous[path][1]:
                absf = abs_path(path)
                hash_cache[path] = val
                sync_to_peers(path, absf, val)

        previous = current
        time.sleep(1)

if __name__ == "__main__":
    load_sinkignore()
    print(f"[sink] Syncing folder: {SYNC_FOLDER}")

    snapshot = snapshot_folder()
    for path, (typ, val) in snapshot.items():
        if typ == "dir":
            mkdir_on_peers(path)
        elif typ == "file":
            absf = abs_path(path)
            hash_cache[path] = val
            sync_to_peers(path, absf, val)

    threading.Thread(target=run_http_server, daemon=True).start()
    start_discovery()
    threading.Thread(target=poll_and_sync, daemon=True).start()
    threading.Thread(target=watch_sinkignore, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[sink] Exiting.")
