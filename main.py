import os
import sys
import threading
import time
import socket
import hashlib
import shutil
import uuid
from pathlib import Path
import fnmatch

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

from auth import (
    add_trusted_device,
    is_device_trusted,
    update_device_ip,
    get_trusted_devices,
)

from conflict import files_conflict

SYNC_FOLDER = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "sync"
SYNC_FOLDER.mkdir(exist_ok=True)
PEER_PORT = 9191
SERVICE_TYPE = "_sinklan._tcp.local."
DEVICE_ID = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-{DEVICE_ID}._sinklan._tcp.local."

SINKIGNORE_PATH = Path(__file__).parent / ".sinkignore"
ignore_patterns = []
ignore_lock = threading.Lock()

# State for sync
known_peers = {}
peer_lock = threading.Lock()
hash_cache = {}
loop_suppress = set()
ready_for_sync = False

def is_tempfile(path):
    return str(path).endswith('.sinktmp')

def relative(p):
    return str(Path(p).relative_to(SYNC_FOLDER)).replace("\\", "/")

def abs_path(rel):
    return (SYNC_FOLDER / rel).resolve()

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

def is_ignored(rel_path):
    rel_path = rel_path.replace("\\", "/")
    with ignore_lock:
        patterns = list(ignore_patterns)
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
    return False

PRIORITY_FILE = SYNC_FOLDER / ".sink_priority"
priority_device_id = None
priority_device_name = None

def load_priority():
    global priority_device_id, priority_device_name
    if PRIORITY_FILE.exists():
        with open(PRIORITY_FILE, "r") as f:
            data = json.load(f)
            priority_device_id = data.get("priority_device_id")
            priority_device_name = data.get("priority_device_name")
        return True
    return False

def save_priority(priority_id, priority_name):
    data = {
        "priority_device_id": priority_id,
        "priority_device_name": priority_name,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    with open(PRIORITY_FILE, "w") as f:
        json.dump(data, f, indent=2)

def wipe_priority():
    if PRIORITY_FILE.exists():
        try:
            PRIORITY_FILE.unlink()
            print("[sink] Wiped .sink_priority on exit.")
        except Exception as e:
            print(f"[sink] Failed to wipe .sink_priority: {e}")

def prompt_for_priority(local_name, local_id, peer_name, peer_id):
    print("Which device should have priority for this sync folder?")
    print(f"1) This device: {local_name} ({local_id})")
    print(f"2) Peer device: {peer_name} ({peer_id})")
    while True:
        selection = input("Enter 1 or 2: ").strip()
        if selection == "1":
            return local_id
        elif selection == "2":
            return peer_id
        else:
            print("Invalid, enter 1 or 2.")

def announce_priority_to_peer(peer_ip, chosen_id, chosen_name):
    try:
        payload = {
            "priority_device_id": chosen_id,
            "priority_device_name": chosen_name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        r = requests.post(f"http://{peer_ip}:{PEER_PORT}/priority", json=payload, timeout=5)
        return r.ok
    except Exception as e:
        print(f"[sink] Failed to announce priority to peer: {e}")
        return False

def get_mutual_peer():
    while True:
        with peer_lock:
            peers = [p for p in known_peers.values() if is_mutual_trust(p["device_id"])]
        if peers:
            peer = peers[0]
            print(f"[sink] Discovered mutual peer: {peer['name']} ({peer['device_id']}) at {peer['ip']}")
            return peer["name"], peer["device_id"], peer["ip"]
        time.sleep(2)

def ensure_priority(peer_name, peer_id, peer_ip):
    local_has_priority = load_priority()
    local_name = socket.gethostname()
    local_id = DEVICE_ID
    if local_has_priority:
        announce_priority_to_peer(peer_ip, priority_device_id, priority_device_name)
        print(f"[sink] Priority already set: {priority_device_id} ({priority_device_name}). Announced to peer.")
        return
    chosen_id = prompt_for_priority(local_name, local_id, peer_name, peer_id)
    if chosen_id == local_id:
        chosen_name = local_name
    else:
        chosen_name = peer_name
    save_priority(chosen_id, chosen_name)
    announce_priority_to_peer(peer_ip, chosen_id, chosen_name)
    print(f"[sink] Priority set: {chosen_id} ({chosen_name})")

def resolve_conflict(rel_path, local_path, incoming_temp_path):
    if not load_priority():
        print("[sink] ERROR: Priority not set! Cannot resolve conflict.")
        return
    if priority_device_id == DEVICE_ID:
        conflict_dir = local_path.parent / ".sink_conflicts"
        conflict_dir.mkdir(exist_ok=True)
        timestamp = int(time.time())
        new_name = f"{local_path.name}.conflict.{timestamp}"
        new_path = conflict_dir / new_name
        shutil.move(str(incoming_temp_path), str(new_path))
        print(f"[sink] CONFLICT: Kept local file, moved incoming to {new_path}")
    else:
        conflict_dir = local_path.parent / ".sink_conflicts"
        conflict_dir.mkdir(exist_ok=True)
        timestamp = int(time.time())
        new_name = f"{local_path.name}.conflict.{timestamp}"
        new_path = conflict_dir / new_name
        shutil.move(str(local_path), str(new_path))
        shutil.move(str(incoming_temp_path), str(local_path))
        print(f"[sink] CONFLICT: Replaced local with incoming, local moved to {new_path}")

def setup_phase_priority():
    peer_name, peer_id, peer_ip = get_mutual_peer()
    ensure_priority(peer_name, peer_id, peer_ip)

peer_status = {}
trusted_by_devices = set()

def update_peer_status(peer_ip, status):
    last_status = peer_status.get(peer_ip)
    if status != last_status:
        if status == "accepted":
            print(f"[sink] Other device {peer_ip} has accepted your device!")
        elif status == "rejected":
            print(f"[sink] Other device {peer_ip} has rejected your device!")
        elif status == "pending":
            print(f"[sink] Waiting for authorization from other device {peer_ip}...")
        peer_status[peer_ip] = status

def notify_peer_trust(peer_ip, peer_id, action):
    try:
        requests.post(
            f"http://{peer_ip}:{PEER_PORT}/trust-notify",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"action": action, "peer_id": DEVICE_ID}),
            timeout=3
        )
    except Exception as e:
        print(f"[sink] Failed to notify peer {peer_ip} of trust action: {e}")

def is_mutual_trust(peer_id):
    return is_device_trusted(peer_id) and (peer_id in trusted_by_devices)

def try_initial_sync(peer_id):
    if is_mutual_trust(peer_id):
        peer_ip = None
        peer_name = None
        with peer_lock:
            for v in known_peers.values():
                if v["device_id"] == peer_id:
                    peer_ip = v["ip"]
                    peer_name = v["name"]
                    break
        if peer_ip:
            threading.Thread(target=initial_sync_to_peer, args=(peer_ip, peer_id, peer_name), daemon=True).start()

def sync_to_peers(rel_path, abs_path, filehash):
    if not ready_for_sync:
        return
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
            }
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", headers=headers, data=data, timeout=5)
            if r.status_code == 202:
                update_peer_status(peer_ip, "pending")
                print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
            elif r.ok:
                update_peer_status(peer_ip, "accepted")
                print(f"[sink] Synced {rel_path} to {peer_ip}")
            elif r.status_code == 403:
                update_peer_status(peer_ip, "rejected")
                print(f"[sink] Peer {peer_ip} rejected sync (not trusted by peer).")
            else:
                print(f"[sink] Sync failed to {peer_ip} (status: {r.status_code})")
        except Exception as e:
            print(f"[sink] Sync failed to {peer_ip}: {e}")

def delete_on_peers(rel_path):
    if not ready_for_sync:
        return
    if is_tempfile(rel_path) or is_ignored(rel_path):
        return
    with peer_lock:
        peers = list(known_peers.values())
    for peer in peers:
        peer_ip = peer["ip"]
        try:
            data = json.dumps({"rel_path": rel_path})
            headers = {"X-Sink-Device-ID": DEVICE_ID}
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/delete", headers=headers, data=data, timeout=5)
            if r.status_code == 202:
                update_peer_status(peer_ip, "pending")
                print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
            elif r.ok:
                update_peer_status(peer_ip, "accepted")
                print(f"[sink] Delete sent for {rel_path} to {peer_ip}")
            elif r.status_code == 403:
                update_peer_status(peer_ip, "rejected")
                print(f"[sink] Peer {peer_ip} rejected delete (not trusted by peer).")
            else:
                print(f"[sink] Delete failed to {peer_ip} (status: {r.status_code})")
        except Exception as e:
            print(f"[sink] Delete failed to {peer_ip}: {e}")

def rename_on_peers(old, new):
    if not ready_for_sync:
        return
    if is_tempfile(old) or is_tempfile(new) or (is_ignored(old) and is_ignored(new)):
        return
    with peer_lock:
        peers = list(known_peers.values())
    for peer in peers:
        peer_ip = peer["ip"]
        try:
            data = json.dumps({"old": old, "new": new})
            headers = {"X-Sink-Device-ID": DEVICE_ID}
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/rename", headers=headers, data=data, timeout=5)
            if r.status_code == 202:
                update_peer_status(peer_ip, "pending")
                print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
            elif r.ok:
                update_peer_status(peer_ip, "accepted")
                print(f"[sink] Rename {old}->{new} sent to {peer_ip}")
            elif r.status_code == 403:
                update_peer_status(peer_ip, "rejected")
                print(f"[sink] Peer {peer_ip} rejected rename (not trusted by peer).")
            else:
                print(f"[sink] Rename failed to {peer_ip} (status: {r.status_code})")
        except Exception as e:
            print(f"[sink] Rename failed to {peer_ip}: {e}")

def resync_unignored_files():
    if not ready_for_sync:
        return
    for root, dirs, files in os.walk(SYNC_FOLDER):
        for fname in files:
            absfile = Path(root) / fname
            rel = relative(absfile)
            if is_tempfile(rel):
                continue
            if not is_ignored(rel):
                h = hash_file(absfile)
                if hash_cache.get(rel) != h:
                    hash_cache[rel] = h
                    sync_to_peers(rel, absfile, h)

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
    resync_unignored_files()

def stable_wait(filepath, timeout=3):
    start = time.time()
    last = -1
    while time.time() - start < timeout:
        try:
            size = os.path.getsize(filepath)
        except Exception:
            return False
        if size == last:
            return True
        last = size
        time.sleep(0.2)
    return False

class SinkIgnoreWatcher(FileSystemEventHandler):
    def __init__(self, watched_path):
        self.watched_path = watched_path

    def on_modified(self, event: FileSystemEvent):
        if Path(event.src_path) == self.watched_path:
            print("[sink] .sinkignore modified, reloading...")
            load_sinkignore()

    def on_created(self, event: FileSystemEvent):
        if Path(event.src_path) == self.watched_path:
            print("[sink] .sinkignore created, reloading...")
            load_sinkignore()

    def on_moved(self, event: FileSystemEvent):
        if Path(event.dest_path) == self.watched_path:
            print("[sink] .sinkignore moved here, reloading...")
            load_sinkignore()
        elif Path(event.src_path) == self.watched_path:
            print("[sink] .sinkignore moved away, patterns cleared.")
            load_sinkignore()

    def on_deleted(self, event: FileSystemEvent):
        if Path(event.src_path) == self.watched_path:
            print("[sink] .sinkignore deleted, patterns cleared.")
            load_sinkignore()

def start_sinkignore_watcher():
    observer = Observer()
    ignore_handler = SinkIgnoreWatcher(SINKIGNORE_PATH)
    observer.schedule(ignore_handler, str(SINKIGNORE_PATH.parent), recursive=False)
    observer.start()
    return observer

class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        device_id = self.headers.get("X-Sink-Device-ID")
        if self.path == "/trust-notify":
            length = int(self.headers.get("Content-Length", 0))
            content = self.rfile.read(length)
            try:
                data = json.loads(content)
                action = data.get("action")
                peer_id = data.get("peer_id")
                if action == "accept":
                    print(f"[sink] Other device has accepted your device (peer_id={peer_id})!")
                    trusted_by_devices.add(peer_id)
                    try_initial_sync(peer_id)
                elif action == "reject":
                    print(f"[sink] Other device has rejected your device (peer_id={peer_id})!")
                    if peer_id in trusted_by_devices:
                        trusted_by_devices.remove(peer_id)
                else:
                    print(f"[sink] Received unknown trust action: {action} from peer {peer_id}")
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                self.send_response(400)
                self.end_headers()
            return

        if self.path == "/priority":
            length = int(self.headers.get("Content-Length", 0))
            content = self.rfile.read(length)
            try:
                data = json.loads(content)
                remote_priority_id = data.get("priority_device_id")
                remote_priority_name = data.get("priority_device_name")
                save_priority(remote_priority_id, remote_priority_name)
                load_priority()
                print(f"[sink] Priority updated via peer: {remote_priority_id} ({remote_priority_name})")
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                print(f"[sink] Failed to process /priority: {e}")
                self.send_response(400)
                self.end_headers()
            return

        if not device_id:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "forbidden", "reason": "Device ID header missing"}).encode())
            return

        if not is_device_trusted(device_id):
            print(f"[sink] Device '{device_id}' not trusted, received {self.path} request and returned pending (202).")
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "pending",
                "reason": "Device not yet authorized. Authorize on this device to proceed."
            }).encode())
            return

        length = int(self.headers.get("Content-Length", 0))
        content = self.rfile.read(length)
        response = {"status": "error"}
        try:
            if self.path == "/sync":
                meta = json.loads(self.headers.get("X-Sink-Meta", "{}"))
                rel_path = meta["rel_path"]
                filehash = meta["hash"]
                if is_tempfile(rel_path) or is_ignored(rel_path):
                    response = {"status": "ignored"}
                elif not ready_for_sync:
                    response = {"status": "notready", "reason": "Priority is not set up"}
                    self.log_message(f"Sync ignored for {rel_path} because priority not ready")
                else:
                    dest = abs_path(rel_path)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    tmp = dest.parent / (dest.name + ".sinktmp")
                    with open(tmp, "wb") as f:
                        f.write(content)
                    if dest.exists() and files_conflict(dest, tmp):
                        resolve_conflict(rel_path, dest, tmp)
                        if priority_device_id != DEVICE_ID:
                            hash_cache[rel_path] = filehash
                        response = {"status": "ok"}
                        self.log_message(f"Conflict handled with priority for {rel_path}")
                    else:
                        shutil.move(tmp, dest)
                        hash_cache[rel_path] = filehash
                        loop_suppress.add(rel_path)
                        response = {"status": "ok"}
                        self.log_message(f"Received {rel_path}")
            elif self.path == "/delete":
                meta = json.loads(content)
                rel_path = meta["rel_path"]
                if is_tempfile(rel_path) or is_ignored(rel_path):
                    response = {"status": "ignored"}
                elif not ready_for_sync:
                    response = {"status": "notready", "reason": "Priority is not set up"}
                    self.log_message(f"Delete ignored for {rel_path} because priority not ready")
                else:
                    dest = abs_path(rel_path)
                    if dest.exists():
                        dest.unlink()
                    response = {"status": "deleted"}
                    self.log_message(f"Deleted {rel_path}")
            elif self.path == "/rename":
                meta = json.loads(content)
                old = meta["old"]
                new = meta["new"]
                if is_tempfile(old) or is_tempfile(new) or is_ignored(old) or is_ignored(new):
                    response = {"status": "ignored"}
                elif not ready_for_sync:
                    response = {"status": "notready", "reason": "Priority is not set up"}
                    self.log_message(f"Rename ignored for {old} -> {new} because priority not ready")
                else:
                    src = abs_path(old)
                    dst = abs_path(new)
                    if src.exists():
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        src.rename(dst)
                        loop_suppress.add(new)
                        response = {"status": "renamed"}
                        self.log_message(f"Renamed {old} to {new}")
                    else:
                        response = {"status": "notfound"}
            else:
                response = {"status": "badpath"}
        except Exception as e:
            response = {"status": "error", "message": str(e)}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        if self.path == "/device_id":
            response = {"device_id": DEVICE_ID, "device_name": socket.gethostname()}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        elif self.path == "/priority":
            if PRIORITY_FILE.exists():
                with open(PRIORITY_FILE, "r") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data.encode())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_http_server():
    server = HTTPServer(("0.0.0.0", PEER_PORT), SinkHandler)
    print(f"[sink] HTTP server listening on {PEER_PORT}")
    server.serve_forever()

def get_peer_device_id(ip):
    try:
        r = requests.get(f"http://{ip}:{PEER_PORT}/device_id", timeout=3)
        if r.ok:
            resp = r.json()
            return resp.get("device_id", ""), resp.get("device_name", ip)
    except Exception:
        pass
    return "", ip

def initial_sync_to_peer(peer_ip, peer_id, peer_name):
    if not ready_for_sync:
        print("[sink] Not ready for sync, skipping initial sync.")
        return
    print(f"[sink] Attempting initial sync to {peer_ip} ...")
    synced_any = False
    any_candidate = False
    for root, dirs, files in os.walk(SYNC_FOLDER):
        for fname in files:
            absfile = Path(root) / fname
            rel = relative(absfile)
            if is_tempfile(rel) or is_ignored(rel):
                continue
            any_candidate = True
            try:
                h = hash_file(absfile)
                with open(absfile, "rb") as f:
                    data = f.read()
                headers = {
                    "X-Sink-Meta": json.dumps({"rel_path": rel, "hash": h}),
                    "X-Sink-Device-ID": DEVICE_ID,
                }
                r = requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", headers=headers, data=data, timeout=5)
                if r.status_code == 202:
                    update_peer_status(peer_ip, "pending")
                    print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
                    return
                if r.status_code in (401, 403):
                    update_peer_status(peer_ip, "rejected")
                    print(f"[sink] Peer {peer_ip} rejected sync ({r.status_code}: not authorized or not trusted).")
                    return
                if r.ok:
                    update_peer_status(peer_ip, "accepted")
                    print(f"[sink]   Synced {rel} to {peer_ip}")
                    synced_any = True
                else:
                    print(f"[sink]   Failed to sync {rel} to {peer_ip} (status: {r.status_code})")
            except Exception as e:
                print(f"[sink]   Error syncing {rel} to {peer_ip}: {e}")
    if synced_any:
        print(f"[sink] Initial sync to {peer_ip} complete.")
    elif any_candidate:
        print(f"[sink] No files were synced to {peer_ip}. Peer may require authorization or trust you back.")
    else:
        print(f"[sink] No files to sync to {peer_ip}.")

class PeerListener:
    def __init__(self, local_ip, trusted_only=False, prompt_on_new=True):
        self.local_ip = local_ip
        self.last_seen = set()
        self.trusted_only = trusted_only
        self.prompt_on_new = prompt_on_new
    def add_service(self, zc, t, name):
        info = zc.get_service_info(t, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip == self.local_ip:
                return
            peer_id, peer_name = get_peer_device_id(ip)
            if not peer_id:
                print(f"[sink] Could not get device ID from {ip}, skipping.")
                return
            trusted = is_device_trusted(peer_id)
            if self.trusted_only and not trusted:
                print(f"[sink] Device '{peer_id}' at {ip} not trusted, ignoring (trusted-only mode).")
                return
            if not trusted:
                if not add_trusted_device(peer_id, peer_name, ip, prompt=self.prompt_on_new, notify_func=notify_peer_trust):
                    return
                print(f"[sink] Device '{peer_id}' trusted.")
                if peer_id in trusted_by_devices:
                    try_initial_sync(peer_id)
            else:
                update_device_ip(peer_id, ip)
            peer_obj = {"ip": ip, "device_id": peer_id, "name": peer_name}
            with peer_lock:
                known_peers[peer_id] = peer_obj
            print(f"[sink] Found new peer: {ip} ({peer_id})")
            if is_mutual_trust(peer_id):
                try_initial_sync(peer_id)
    def remove_service(self, zc, t, name):
        info = zc.get_service_info(t, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            did = None
            with peer_lock:
                for k, v in list(known_peers.items()):
                    if v["ip"] == ip:
                        did = k
                        del known_peers[k]
                        print(f"[sink] Disconnected from peer {ip} ({did}), searching again...")
                        break

    def update_service(self, zc, t, name):
        pass

def start_discovery(trusted_only=False, prompt_on_new=True):
    zeroconf = Zeroconf()
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(get_local_ip())],
        port=PEER_PORT,
        properties={},
        server=socket.gethostname() + ".local."
    )
    zeroconf.register_service(info)
    listener = PeerListener(get_local_ip(), trusted_only=trusted_only, prompt_on_new=prompt_on_new)
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    print("[sink] Zeroconf service running")
    return zeroconf

class SinkEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not ready_for_sync:
            return
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
        if is_ignored(rel):
            return
        if rel in loop_suppress:
            loop_suppress.discard(rel)
            return
        if not stable_wait(event.src_path):
            print(f"[sink] Skipped unstable {rel}")
            return
        h = hash_file(event.src_path)
        if hash_cache.get(rel) == h:
            return
        hash_cache[rel] = h
        sync_to_peers(rel, event.src_path, h)

    def on_created(self, event):
        if not ready_for_sync:
            return
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
        if is_ignored(rel):
            return
        self.on_modified(event)

    def on_deleted(self, event):
        if not ready_for_sync:
            return
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
        if is_ignored(rel):
            return
        if rel in loop_suppress:
            loop_suppress.discard(rel)
            return
        hash_cache.pop(rel, None)
        delete_on_peers(rel)

    def on_moved(self, event):
        if not ready_for_sync:
            return
        if event.is_directory or is_tempfile(event.dest_path) or is_tempfile(event.src_path):
            return
        src_rel = relative(event.src_path)
        dst_rel = relative(event.dest_path)
        if is_ignored(src_rel) and is_ignored(dst_rel):
            return
        hash_cache.pop(src_rel, None)
        if not is_ignored(dst_rel):
            hash_cache[dst_rel] = hash_file(event.dest_path) if os.path.isfile(event.dest_path) else None
        rename_on_peers(src_rel, dst_rel)

def start_watcher():
    event_handler = SinkEventHandler()
    observer = Observer()
    observer.schedule(event_handler, str(SYNC_FOLDER), recursive=True)
    observer.start()
    print(f"[sink] Watching {SYNC_FOLDER}")
    return observer

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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="sink file sync")
    parser.add_argument("--trusted-only", action="store_true", help="Only sync with trusted devices")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for new devices, always trust")
    args = parser.parse_args()

    load_sinkignore()
    print(f"[sink] Sync folder: {SYNC_FOLDER}")
    threading.Thread(target=run_http_server, daemon=True).start()
    ignore_observer = start_sinkignore_watcher()
    zc = start_discovery(trusted_only=args.trusted_only, prompt_on_new=not args.no_prompt)
    print("[sink] Waiting for peers (start a second instance)...")

    setup_phase_priority()
    ready_for_sync = True

    folder_observer = start_watcher()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        folder_observer.stop()
        ignore_observer.stop()
    folder_observer.join()
    ignore_observer.join()
    zc.close()
    wipe_priority()