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
import ssl

import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser

# unissueing rn
# iykyk
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import datetime
except ImportError:
    print("cryp imports got cryp")
    sys.exit(2)


SYNC_FOLDER = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "sync"
SYNC_FOLDER.mkdir(exist_ok=True)
PEER_PORT = 9191
SERVICE_TYPE = "_sinklan._tcp.local."
DEVICE_ID = str(uuid.uuid4())[:8]
SERVICE_NAME = f"sink-{DEVICE_ID}._sinklan._tcp.local."

CONFIG_DIR = Path(__file__).parent / ".sink_config"
CONFIG_DIR.mkdir(exist_ok=True)

SINKIGNORE_PATH = Path(__file__).parent / ".sinkignore"
ignore_patterns = []
ignore_lock = threading.Lock()

DEVICES_FILE = CONFIG_DIR / "devices.json"
CERT_FILE = CONFIG_DIR / "cert.pem"
KEY_FILE = CONFIG_DIR / "key.pem"
CERT_FINGERPRINT = None

conflicted_paths = set()
conflicted_paths_lock = threading.Lock()
known_peers = {}
peer_status = {}
peer_lock = threading.Lock()

def generate_self_signed_cert():
    #is your baby crying? i'll make them have encryption! please encryypt please encryyppt! please encry-y-y-y-ypt!
    global CERT_FINGERPRINT
    if CERT_FILE.exists() and KEY_FILE.exists():
        with open(CERT_FILE, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            CERT_FINGERPRINT = cert.fingerprint(hashes.SHA256()).hex()
        print("[sink] SSL certificate already exists.")
        return

    print("[sink] Generating a new SSL cert...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Colorado"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Denver"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SinkLAN"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"sink-{DEVICE_ID}"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    CERT_FINGERPRINT = cert.fingerprint(hashes.SHA256()).hex()
    print(f"[sink] New SSL certificate generated. Fingerprint: {CERT_FINGERPRINT[:16]}...")

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
    except (IOError, OSError):
        return None

def files_conflict(local_path, incoming_temp_path):
    h1 = hash_file(local_path)
    h2 = hash_file(incoming_temp_path)
    return h1 is not None and h2 is not None and h1 != h2

def handle_conflict(rel_path, local_path, incoming_temp_path, remote_device_name):
    device_name = get_hostname()
    conflict_base = Path(local_path).parent / ".sink_conflicts"
    local_conflict_dir = conflict_base / device_name
    remote_conflict_dir = conflict_base / remote_device_name

    local_conflict_dir.mkdir(parents=True, exist_ok=True)
    remote_conflict_dir.mkdir(parents=True, exist_ok=True)

    local_hash = hash_file(local_path)
    remote_hash = hash_file(incoming_temp_path)

    if not local_hash or not remote_hash:
        print(f"[sink] Could not hash conflicting files for {rel_path}, using timestamp fallback.")
        local_hash = remote_hash = str(int(time.time()))
    
    rel_filename = Path(rel_path).name
    local_conflict_file = local_conflict_dir / f"{local_hash[:8]}-{rel_filename}"
    remote_conflict_file = remote_conflict_dir / f"{remote_hash[:8]}-{rel_filename}"

    if Path(local_path).exists():
        if not local_conflict_file.exists():
            shutil.move(str(local_path), str(local_conflict_file))
            print(f"[sink] Local conflicting file moved to {local_conflict_file}")
        else:
            Path(local_path).unlink(missing_ok=True)

    if Path(incoming_temp_path).exists():
        if not remote_conflict_file.exists():
            shutil.move(str(incoming_temp_path), str(remote_conflict_file))
            print(f"[sink] Incoming conflicting file moved to {remote_conflict_file}")
        else:
            Path(incoming_temp_path).unlink(missing_ok=True)

    print(f"[sink] Conflict for {rel_path} handled. Versions stored in .sink_conflicts/")

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
        print(f"[sink] Trusting new device: {name} ({device_id})")
    devices[device_id] = {"device_id": device_id, "name": name, "last_ip": ip}
    save_trusted_devices(devices)
    return True

def update_device_ip(device_id, ip):
    devices = load_trusted_devices()
    if device_id in devices:
        devices[device_id]["last_ip"] = ip
        save_trusted_devices(devices)

def sync_folder_to_peer(peer):
    peer_ip = peer['ip']
    print(f"[sink] Performing initial sync with {peer['name']} ({peer_ip})")
    snapshot = snapshot_folder()
    for path, (typ, val) in snapshot.items():
        if is_ignored(path) or is_tempfile(path):
            continue
        if typ == "dir":
            mkdir_on_peers(path)
        elif typ == "file":
            absf = abs_path(path)
            sync_to_peers(path, absf, val)

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

        if self.path == "/auth":
            if not device_id:
                self.send_response(400, "Device ID header missing")
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            action = data.get('action')

            with peer_lock:
                if action == 'request_trust':
                    peer_ip = self.client_address[0]
                    if is_device_trusted(device_id):
                        try:
                            headers = {'X-Sink-Device-ID': DEVICE_ID, 'X-Sink-Device-Name': get_hostname()}
                            requests.post(f"http://{peer_ip}:{PEER_PORT}/auth", headers=headers, json={'action': 'confirm_trust'}, timeout=5)
                        except requests.exceptions.RequestException: pass
                    elif device_id in peer_status:
                        state = peer_status[device_id]['state']
                        if state == 'requested': 
                            print(f"\n[sink] Mutual trust with {remote_device_name} ({device_id}).")
                            add_trusted_device(device_id, remote_device_name, peer_ip)
                            newly_trusted_peer = peer_status.pop(device_id)
                            known_peers[device_id] = newly_trusted_peer
                            try:
                                headers = {'X-Sink-Device-ID': DEVICE_ID, 'X-Sink-Device-Name': get_hostname()}
                                requests.post(f"http://{peer_ip}:{PEER_PORT}/auth", headers=headers, json={'action': 'confirm_trust'}, timeout=5)
                            except requests.exceptions.RequestException: pass
                            threading.Thread(target=sync_folder_to_peer, args=(newly_trusted_peer,), daemon=True).start()
                        else: 
                            peer_status[device_id]['state'] = 'approved'
                            print(f"\n[sink] {remote_device_name} ({device_id}) wants to sync.")
                            print(f"[sink] To approve, type 'trust {device_id}'")
                    else:
                        peer_status[device_id] = {'name': remote_device_name, 'ip': peer_ip, 'state': 'approved'}
                        print(f"\n[sink] {remote_device_name} ({device_id}) wants to sync.")
                        print(f"[sink] To approve, type 'trust {device_id}'")

                elif action == 'confirm_trust':
                    if device_id in peer_status and peer_status[device_id]['state'] == 'requested':
                        print(f"\n[sink] {remote_device_name} ({device_id}) confirmed trust.")
                        add_trusted_device(device_id, remote_device_name, self.client_address[0])
                        newly_trusted_peer = peer_status.pop(device_id)
                        known_peers[device_id] = newly_trusted_peer
                        threading.Thread(target=sync_folder_to_peer, args=(newly_trusted_peer,), daemon=True).start()

            self.send_response(200)
            self.end_headers()
            return

        if not device_id or not is_device_trusted(device_id):
            self.send_response(403, "Device not trusted")
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        content = self.rfile.read(length)

        if self.path == "/sync":
            meta = json.loads(self.headers.get("X-Sink-Meta", "{}"))
            rel_path = meta["rel_path"]
            dest = abs_path(rel_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".sinktmp")
            
            with open(tmp, "wb") as f:
                f.write(content)
            
            if dest.exists() and files_conflict(dest, tmp):
                handle_conflict(rel_path, dest, tmp, remote_device_name)
                with conflicted_paths_lock:
                    conflicted_paths.add(rel_path)
            else:
                shutil.move(tmp, dest)

            self.send_response(200)
            self.end_headers()

        elif self.path == "/delete":
            meta = json.loads(content)
            rel_path = meta["rel_path"]
            path = abs_path(rel_path)
            if path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
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
            except OSError:
                pass
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
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
            if ip == self.local_ip: return
            try:
                r = requests.get(f"http://{ip}:{PEER_PORT}/device_id", timeout=2)
                if r.ok:
                    data = r.json()
                    peer_id, peer_name = data["device_id"], data["device_name"]
                    if peer_id == DEVICE_ID: return
                    
                    with peer_lock:
                        if is_device_trusted(peer_id):
                            if peer_id not in known_peers:
                                print(f"[sink] Found trusted peer {peer_name} ({ip})")
                                update_device_ip(peer_id, ip)
                                peer_info = {"ip": ip, "device_id": peer_id, "name": peer_name}
                                known_peers[peer_id] = peer_info
                                threading.Thread(target=sync_folder_to_peer, args=(peer_info,), daemon=True).start()
                        elif peer_id not in peer_status:
                            peer_status[peer_id] = {"name": peer_name, "ip": ip, "state": "pending"}
                            print(f"\n[sink] Discovered new device: {peer_name} ({peer_id}).")
                            print(f"[sink] To connect, type 'trust {peer_id}'")
            except requests.exceptions.RequestException:
                pass

    def remove_service(self, *args): pass
    def update_service(self, *args): pass

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
        for d in list(dirs):
            path = Path(root) / d
            rel = relative(path)
            if is_ignored(rel) or is_tempfile(rel):
                dirs.remove(d) 
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
    previous = snapshot_folder()
    print("[sink] Polling every 1s")
    while True:
        current = snapshot_folder()
        
        with conflicted_paths_lock:
            for path in list(conflicted_paths):
                if path in previous:
                    del previous[path]
                conflicted_paths.remove(path)

        added = set(current) - set(previous)
        removed = set(previous) - set(current)
        common = set(current) & set(previous)

        for path in added:
            typ, val = current[path]
            if typ == "dir":
                mkdir_on_peers(path)
            else:
                absf = abs_path(path)
                sync_to_peers(path, absf, val)

        for path in sorted(list(removed), key=len, reverse=True):
            typ, val = previous[path]
            if typ == "dir":
                rmdir_on_peers(path)
            else:
                delete_on_peers(path)

        for path in common:
            typ, val = current[path]
            if typ == "file" and val != previous.get(path, (None, None))[1]:
                absf = abs_path(path)
                sync_to_peers(path, absf, val)

        previous = current
        time.sleep(1)

def handle_user_input():
    time.sleep(2) 
    print("\n[sink] Ready. Type 'devices' to see discovered devices or 'trust <id>' to connect.")
    while True:
        try:
            cmd = input("> ")
            parts = cmd.strip().split()
            if not parts: continue
            
            command = parts[0].lower()
            if command == 'trust' and len(parts) > 1:
                peer_id = parts[1]
                with peer_lock:
                    if is_device_trusted(peer_id):
                        print(f"[sink] Device {peer_id} is already trusted.")
                    elif peer_id in peer_status:
                        peer_info = peer_status[peer_id]
                        state = peer_info['state']
                        if state == 'pending':
                            peer_info['state'] = 'requested'
                            print(f"[sink] Requesting to sync with {peer_info['name']}.")
                            try:
                                headers = {'X-Sink-Device-ID': DEVICE_ID, 'X-Sink-Device-Name': get_hostname()}
                                requests.post(f"http://{peer_info['ip']}:{PEER_PORT}/auth", headers=headers, json={'action': 'request_trust'}, timeout=5)
                                print(f"[sink] Request sent. Please approve on {peer_info['name']} as well.")
                            except requests.exceptions.RequestException as e:
                                print(f"[sink] Could not connect to {peer_info['name']}: {e}")
                                peer_info['state'] = 'pending' 
                        elif state == 'approved': 
                            print(f"[sink] Approving request from {peer_info['name']}.")
                            add_trusted_device(peer_id, peer_info['name'], peer_info['ip'])
                            newly_trusted_peer = peer_status.pop(peer_id)
                            known_peers[peer_id] = newly_trusted_peer
                            try:
                                headers = {'X-Sink-Device-ID': DEVICE_ID, 'X-Sink-Device-Name': get_hostname()}
                                requests.post(f"http://{peer_info['ip']}:{PEER_PORT}/auth", headers=headers, json={'action': 'confirm_trust'}, timeout=5)
                            except requests.exceptions.RequestException: pass
                            threading.Thread(target=sync_folder_to_peer, args=(newly_trusted_peer,), daemon=True).start()
                        elif state == 'requested':
                            print("[sink] Already requested. Waiting for them to approve.")
                    else:
                        print(f"[sink] Device {peer_id} not found. Waiting for discovery...")

            elif command == 'devices':
                print("\n--- sink LAN Devices ---")
                trusted_devices = load_trusted_devices()
                online_trusted = {p for p in known_peers}
                
                if trusted_devices:
                    print("Trusted:")
                    for dev_id, dev_info in trusted_devices.items():
                        status = "online" if dev_id in online_trusted else "offline"
                        print(f"  - {dev_info['name']} ({dev_id}) [{status}]")
                
                with peer_lock:
                    pending = {k:v for k,v in peer_status.items() if v['state'] == 'pending'}
                    approved = {k:v for k,v in peer_status.items() if v['state'] == 'approved'}
                    requested = {k:v for k,v in peer_status.items() if v['state'] == 'requested'}

                    if pending:
                        print("Discovered (can be trusted):")
                        for peer_id, peer_info in pending.items():
                            print(f"  - {peer_info['name']} ({peer_id})")
                    if approved:
                        print("Needs your approval:")
                        for peer_id, peer_info in approved.items():
                             print(f"  - {peer_info['name']} ({peer_id})")
                    if requested:
                        print("Awaiting their approval:")
                        for peer_id, peer_info in requested.items():
                             print(f"  - {peer_info['name']} ({peer_id})")
                if not (trusted_devices or peer_status):
                    print("No other devices found yet.")
                print("------------------------")
            else:
                print(f"Unknown command. Available: devices, trust <device_id>")
        except (EOFError, KeyboardInterrupt):
            break
        except Exception as e:
            print(f"[sink] Error in command handler: {e}")

if __name__ == "__main__":
    load_sinkignore()
    print(f"[sink] Syncing folder: {SYNC_FOLDER}")
    print(f"[sink] My device ID: {DEVICE_ID}")

    threading.Thread(target=run_http_server, daemon=True).start()
    start_discovery()
    threading.Thread(target=poll_and_sync, daemon=True).start()
    threading.Thread(target=watch_sinkignore, daemon=True).start()
    threading.Thread(target=handle_user_input, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[sink] Exiting.")