import hashlib

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
    return h1 is not None and h2 is not None and h1 != h2