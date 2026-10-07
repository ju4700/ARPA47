import os
import zipfile
import hashlib
from concurrent.futures import ProcessPoolExecutor

V2_DIR = r"F:\ARPA47-Dataset\zeek_v2"
OUTPUT_DIR = r"F:\ARPA47-Dataset\zenodo_export"

def hash_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192 * 1024):
            h.update(chunk)
    return os.path.basename(filepath), h.hexdigest()

def zip_folder(folder_name):
    folder_path = os.path.join(V2_DIR, folder_name)
    zip_path = os.path.join(OUTPUT_DIR, f"arpa47_{folder_name}.zip")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for f in os.listdir(folder_path):
            if f.endswith('.parquet'):
                zipf.write(os.path.join(folder_path, f), arcname=f)
    return zip_path

if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 1. Zip the folders
    folders = ['conn', 'dns', 'http', 'quic', 'ssl', 'weird']
    print("Zipping dataset folders...")
    with ProcessPoolExecutor(max_workers=4) as ex:
        zip_files = list(ex.map(zip_folder, folders))
    
    # 2. Copy manifest
    import shutil
    shutil.copy2(os.path.join(V2_DIR, 'manifest.csv'), os.path.join(OUTPUT_DIR, 'manifest.csv'))
    zip_files.append(os.path.join(OUTPUT_DIR, 'manifest.csv'))
    
    # 3. Hash everything
    print("Generating SHA-256 checksums...")
    with ProcessPoolExecutor(max_workers=4) as ex:
        hashes = list(ex.map(hash_file, zip_files))
        
    with open(os.path.join(OUTPUT_DIR, 'checksums.sha256'), 'w') as f:
        for name, h in hashes:
            f.write(f"{h}  {name}\n")
            
    print("Zenodo payload generation complete.")
