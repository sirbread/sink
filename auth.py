import json
from pathlib import Path

DEVICES_FILE = Path(__file__).parent/ "devices.json"

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

def add_trusted_device(device_id, name, ip, prompt=False, notify_func=None):
    devices = load_trusted_devices()
    if device_id not in devices:
        if prompt:
            resp = input(f"[sink] New device '{device_id}' ({name}) at {ip} discovered. Trust this device? [Y/n] ").strip().lower()
            if resp and resp.startswith("n"):
                print(f"[sink] Device '{device_id}' not trusted, will ignore.")
                if notify_func:
                    notify_func(ip, device_id, "reject")
                return False
            else:
                if notify_func:
                    notify_func(ip, device_id, "accept")
        else:
            print(f"[sink] Trusting new device: {device_id} ({name}) at {ip}")
            if notify_func:
                notify_func(ip, device_id, "accept")
    devices[device_id] = {"device_id": device_id, "name": name, "last_ip": ip}
    save_trusted_devices(devices)
    return True

def update_device_ip(device_id, ip):
    devices = load_trusted_devices()
    if device_id in devices:
        devices[device_id]["last_ip"] = ip
        save_trusted_devices(devices)

def is_device_trusted(device_id):
    devices = load_trusted_devices()
    return device_id in devices

def get_trusted_devices():
    return load_trusted_devices()

def remove_trusted_device(device_id):
    devices = load_trusted_devices()
    if device_id in devices:
        del devices[device_id]
        save_trusted_devices(devices)

def list_trusted_devices():
    devices = get_trusted_devices()
    if not devices:
        print("[sink] No trusted devices.")
        return
    print("[sink] Trusted devices:")
    for d in devices.values():
        print(f"  - {d['device_id']} ({d['name']}) last seen at {d['last_ip']}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Trusted devices management for sink.")
    parser.add_argument("--list", action="store_true", help="List all trusted devices")
    parser.add_argument("--add", nargs=3, metavar=("DEVICE_ID", "NAME", "IP"), help="Add a trusted device")
    parser.add_argument("--remove", metavar="DEVICE_ID", help="Remove a trusted device")
    args = parser.parse_args()
    if args.list:
        list_trusted_devices()
    elif args.add:
        device_id, name, ip = args.add
        add_trusted_device(device_id, name, ip)
        print("[sink] Device added.")
    elif args.remove:
        remove_trusted_device(args.remove)
        print("[sink] Device removed.")
    else:
        parser.print_help()
