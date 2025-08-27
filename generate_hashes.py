import os
import json
import hashlib

def file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_reference_hashes(directory, file_extensions=(".py", ".html", ".css", ".jpg", ".js")):
    ref_hashes = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(file_extensions):
                full_path = os.path.join(root, file)
                # Сохраняем путь относительно корневой директории
                rel_path = os.path.relpath(full_path, directory)
                ref_hashes[rel_path] = file_sha256(full_path)
    return ref_hashes

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    hashes = generate_reference_hashes(base_dir)
    with open("integrity_reference.json", "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=4, ensure_ascii=False)
    print("Эталонные хэши сохранены в integrity_reference.json")
