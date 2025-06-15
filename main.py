import os
import time
import hashlib
import socket
import threading
import requests
import uuid
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

from fastapi import FastAPI, UploadFile, File
import uvicorn

FOLDER_TO_SYNC = Path(__file__).parent.resolve() / "sync"
PEER_PORT = 9001
SERVICE_TYPE = "_sink._tcp.local."

unique_id = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-peer-{unique_id}._sink._tcp.local."

file_hash_cache = {}

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
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

class SyncHandler(FileSystemEventHandler):
    def __init__(self, peer_ip):
        self.peer_ip = peer_ip

    def on_modified(self, event):
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        new_hash = hash_file(file_path)

        if file_path.name in file_hash_cache and file_hash_cache[file_path.name] == new_hash:
            return

        file_hash_cache[file_path.name] = new_hash
        print(f"sending {file_path} to peer")

        try:
            files = {'file': open(file_path, 'rb')}
            requests.post(f"http://{self.peer_ip}:{PEER_PORT}/sync", files=files, timeout=5)
        except Exception as e:
            print(f"failed to sync file: {e}")

app = FastAPI()

@app.post("/sync")
async def sync_file(file: UploadFile = File(...)):
    path = FOLDER_TO_SYNC / file.filename
    path.parent.mkdir(parents=True, exist_ok=True)
    contents = await file.read()
    path.write_bytes(contents)
    file_hash_cache[file.filename] = hashlib.sha256(contents).hexdigest()
    print(f"received: {file.filename} -> wrote to {path.resolve()} ({len(contents)} bytes)")
    return {"status": "ok"}

def sync_all_files_to_peer(peer_ip):
    print(f"performing initial sync to peer {peer_ip}")
    for filepath in FOLDER_TO_SYNC.rglob("*"):
        if filepath.is_file():
            file_name = filepath.name
            local_hash = hash_file(filepath)
            cached_hash = file_hash_cache.get(file_name)
            if cached_hash == local_hash:
                continue
            file_hash_cache[file_name] = local_hash
            print(f"sending {filepath} to peer during initial sync")
            try:
                with open(filepath, 'rb') as f:
                    files = {'file': f}
                    requests.post(f"http://{peer_ip}:{PEER_PORT}/sync", files=files, timeout=5)
            except Exception as e:
                print(f"failed to sync file {file_name}: {e}")

class SinkPeerListener:
    def __init__(self, local_ip):
        self.peer_ip = None
        self.local_ip = local_ip

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip == self.local_ip:
                return
            if self.peer_ip != ip:
                self.peer_ip = ip
                print(f"found peer: {self.peer_ip}")
                threading.Thread(target=sync_all_files_to_peer, args=(self.peer_ip,), daemon=True).start()

    def remove_service(self, zeroconf, type, name):
        pass

    def update_service(self, zeroconf, type, name):
        pass

if __name__ == "__main__":
    FOLDER_TO_SYNC.mkdir(exist_ok=True)

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

    def monitor_peer(listener):
        while True:
            if listener.peer_ip:
                try:
                    requests.head(f"http://{listener.peer_ip}:{PEER_PORT}/sync", timeout=2)
                except Exception:
                    print(f"peer {listener.peer_ip} disconnected")
                    listener.peer_ip = None
                    print("waiting for peer...")
            time.sleep(7)

    threading.Thread(target=monitor_peer, args=(listener,), daemon=True).start()

    print("waiting for peer...")
    while listener.peer_ip is None:
        time.sleep(1)

    print("watching for changes")
    event_handler = SyncHandler(listener.peer_ip)
    observer = Observer()
    observer.schedule(event_handler, str(FOLDER_TO_SYNC), recursive=True)
    observer.start()

    try:
        while True:
            if listener.peer_ip is None:
                print("waiting for peer...")
                while listener.peer_ip is None:
                    time.sleep(1)
                observer.stop()
                observer.join()
                event_handler = SyncHandler(listener.peer_ip)
                observer = Observer()
                observer.schedule(event_handler, str(FOLDER_TO_SYNC), recursive=True)
                observer.start()
                print(f"peer reconnected: {listener.peer_ip}")
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        zeroconf.unregister_service(info)
        zeroconf.close()
        observer.join()

