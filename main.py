import os
import sys
import threading
import time
import socket
import hashlib
import shutil
import uuid
from pathlib import Path

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser

from http.server import HTTPServer, BaseHTTPRequestHandler
import json


SYNC_FOLDER = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "sync"
SYNC_FOLDER.mkdir(exist_ok=True)
PEER_PORT = 9191
SERVICE_TYPE = "_sinklan._tcp.local."
DEVICE_ID = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-{DEVICE_ID}._sinklan._tcp.local."

known_peers = set()
peer_lock = threading.Lock()
hash_cache = {}
loop_suppress = set()

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

def relative(p):
    return str(Path(p).relative_to(SYNC_FOLDER)).replace("\\", "/")

def abs_path(rel):
    return (SYNC_FOLDER / rel).resolve()

def stable_wait(filepath, timeout=3):
    "Wait until file stops changing size, or timeout"
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

def is_tempfile(path):
    return str(path).endswith('.sinktmp')

class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        content = self.rfile.read(length)
        response = {"status": "error"}
        try:
            if self.path == "/sync":
                meta = json.loads(self.headers.get("X-Sink-Meta", "{}"))
                rel_path = meta["rel_path"]
                filehash = meta["hash"]
                if is_tempfile(rel_path):
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
                if is_tempfile(rel_path):
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
                if is_tempfile(old) or is_tempfile(new):
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

def run_http_server():
    server = HTTPServer(("0.0.0.0", PEER_PORT), SinkHandler)
    print(f"[sink] HTTP server listening on {PEER_PORT}")
    server.serve_forever()

def initial_sync_to_peer(peer_ip):
    print(f"[sink] Performing initial sync to {peer_ip} ...")
    for root, dirs, files in os.walk(SYNC_FOLDER):
        for fname in files:
            absfile = Path(root) / fname
            rel = relative(absfile)
            if is_tempfile(rel):
                continue
            try:
                h = hash_file(absfile)
                with open(absfile, "rb") as f:
                    data = f.read()
                headers = {
                    "X-Sink-Meta": json.dumps({"rel_path": rel, "hash": h})
                }
                r = requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", headers=headers, data=data, timeout=5)
                if r.ok:
                    print(f"[sink]   Synced {rel} to {peer_ip}")
                else:
                    print(f"[sink]   Failed to sync {rel} to {peer_ip}")
            except Exception as e:
                print(f"[sink]   Error syncing {rel} to {peer_ip}: {e}")

class PeerListener:
    def __init__(self, local_ip):
        self.local_ip = local_ip
        self.last_seen = set() 
    def add_service(self, zc, t, name):
        info = zc.get_service_info(t, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip != self.local_ip:
                first_time = False
                with peer_lock:
                    if ip not in known_peers:
                        known_peers.add(ip)
                        first_time = True
                if first_time or ip not in self.last_seen:
                    print(f"[sink] Found new peer: {ip}")
                    threading.Thread(target=initial_sync_to_peer, args=(ip,), daemon=True).start()
                self.last_seen.add(ip)
    def remove_service(self, zc, t, name):
        info = zc.get_service_info(t, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            with peer_lock:
                if ip in known_peers:
                    known_peers.discard(ip)
                    print(f"[sink] Peer {ip} left")
    def update_service(self, zc, t, name):
        pass

def start_discovery():
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
    listener = PeerListener(get_local_ip())
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    print("[sink] Zeroconf service running")
    return zeroconf

class SinkEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
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
        self.on_modified(event)

    def on_deleted(self, event):
        if event.is_directory or is_tempfile(event.src_path):
            return
        rel = relative(event.src_path)
        hash_cache.pop(rel, None)
        delete_on_peers(rel)

    def on_moved(self, event):
        if event.is_directory or is_tempfile(event.dest_path) or is_tempfile(event.src_path):
            return
        src_rel = relative(event.src_path)
        dst_rel = relative(event.dest_path)
        hash_cache.pop(src_rel, None)
        hash_cache[dst_rel] = hash_file(event.dest_path) if os.path.isfile(event.dest_path) else None
        rename_on_peers(src_rel, dst_rel)

def start_watcher():
    event_handler = SinkEventHandler()
    observer = Observer()
    observer.schedule(event_handler, str(SYNC_FOLDER), recursive=True)
    observer.start()
    print(f"[sink] Watching {SYNC_FOLDER}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def sync_to_peers(rel_path, abs_path, filehash):
    if is_tempfile(rel_path):
        return
    with peer_lock:
        peers = list(known_peers)
    for peer_ip in peers:
        try:
            with open(abs_path, "rb") as f:
                data = f.read()
            headers = {
                "X-Sink-Meta": json.dumps({"rel_path": rel_path, "hash": filehash})
            }
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", headers=headers, data=data, timeout=5)
            if r.ok:
                print(f"[sink] Synced {rel_path} to {peer_ip}")
        except Exception as e:
            print(f"[sink] Sync failed to {peer_ip}: {e}")

def delete_on_peers(rel_path):
    if is_tempfile(rel_path):
        return
    with peer_lock:
        peers = list(known_peers)
    for peer_ip in peers:
        try:
            data = json.dumps({"rel_path": rel_path})
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/delete", data=data, timeout=5)
            if r.ok:
                print(f"[sink] Delete sent for {rel_path} to {peer_ip}")
        except Exception as e:
            print(f"[sink] Delete failed to {peer_ip}: {e}")

def rename_on_peers(old, new):
    if is_tempfile(old) or is_tempfile(new):
        return
    with peer_lock:
        peers = list(known_peers)
    for peer_ip in peers:
        try:
            data = json.dumps({"old": old, "new": new})
            r = requests.post(f"http://{peer_ip}:{PEER_PORT}/rename", data=data, timeout=5)
            if r.ok:
                print(f"[sink] Rename {old}->{new} sent to {peer_ip}")
        except Exception as e:
            print(f"[sink] Rename failed to {peer_ip}: {e}")


if __name__ == "__main__":
    print(f"[sink] Sync folder: {SYNC_FOLDER}")
    threading.Thread(target=run_http_server, daemon=True).start()
    zc = start_discovery()
    print("[sink] Waiting for peers (start a second instance)...")
    for _ in range(60):
        with peer_lock:
            if known_peers:
                break
        time.sleep(1)
    start_watcher()
    zc.close()
