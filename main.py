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

SYNC_FOLDER = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "sync"
SYNC_FOLDER.mkdir(exist_ok=True)
PEER_PORT = 9191
SERVICE_TYPE = "_sinklan._tcp.local."
DEVICE_ID = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-{DEVICE_ID}._sinklan._tcp.local."

SINKIGNORE_PATH = Path(__file__).parent / ".sinkignore"
ignore_patterns = []
ignore_lock = threading.Lock()

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
            }
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", headers=headers, data=data, timeout=5)
            if r.status_code == 202:
                print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
            elif r.ok:
                print(f"[sink] Synced {rel_path} to {peer_ip}")
            elif r.status_code == 403:
                print(f"[sink] Peer {peer_ip} rejected sync (not trusted by peer).")
            else:
                print(f"[sink] Sync failed to {peer_ip} (status: {r.status_code})")
        except Exception as e:
            print(f"[sink] Sync failed to {peer_ip}: {e}")

def delete_on_peers(rel_path):
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
                print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
            elif r.ok:
                print(f"[sink] Delete sent for {rel_path} to {peer_ip}")
            elif r.status_code == 403:
                print(f"[sink] Peer {peer_ip} rejected delete (not trusted by peer).")
            else:
                print(f"[sink] Delete failed to {peer_ip} (status: {r.status_code})")
        except Exception as e:
            print(f"[sink] Delete failed to {peer_ip}: {e}")

def rename_on_peers(old, new):
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
                print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
            elif r.ok:
                print(f"[sink] Rename {old}->{new} sent to {peer_ip}")
            elif r.status_code == 403:
                print(f"[sink] Peer {peer_ip} rejected rename (not trusted by peer).")
            else:
                print(f"[sink] Rename failed to {peer_ip} (status: {r.status_code})")
        except Exception as e:
            print(f"[sink] Rename failed to {peer_ip}: {e}")

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

known_peers = {}
peer_lock = threading.Lock()
hash_cache = {}
loop_suppress = set()

def resync_unignored_files():
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
        if not device_id:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "forbidden", "reason": "Device ID header missing"}).encode())
            return

        if not is_device_trusted(device_id):
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
                else:
                    dest = abs_path(rel_path)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    tmp = dest.parent / (dest.name + ".sinktmp")
                    with open(tmp, "wb") as f:
                        f.write(content)
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
                    print(f"[sink] You must authorize on the other device for sink! ({peer_ip})")
                    return
                if r.status_code in (401, 403):
                    print(f"[sink] Peer {peer_ip} rejected sync ({r.status_code}: not authorized or not trusted).")
                    return
                if r.ok:
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
                if not add_trusted_device(peer_id, peer_name, ip, prompt=self.prompt_on_new):
                    return
                print(f"[sink] Device '{peer_id}' trusted.")
                if peer_id in known_peers:
                    print(f"[sink] Now mutually trusted with {ip} ({peer_id}), triggering initial sync.")
                    threading.Thread(target=initial_sync_to_peer, args=(ip, peer_id, peer_name), daemon=True).start()
            else:
                update_device_ip(peer_id, ip)
            peer_obj = {"ip": ip, "device_id": peer_id, "name": peer_name}
            with peer_lock:
                known_peers[peer_id] = peer_obj
            print(f"[sink] Found new peer: {ip} ({peer_id})")
            threading.Thread(target=initial_sync_to_peer, args=(ip, peer_id, peer_name), daemon=True).start()
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
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
        if is_ignored(rel):
            return
        self.on_modified(event)

    def on_deleted(self, event):
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
        if is_ignored(rel):
            return
        hash_cache.pop(rel, None)
        delete_on_peers(rel)

    def on_moved(self, event):
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
    for _ in range(60):
        with peer_lock:
            if known_peers:
                break
        time.sleep(1)

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
