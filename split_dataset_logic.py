import os
import glob
import shutil
import zipfile

SOURCE_DIR = r"F:\ARPA47-Dataset\ARPA47_Release"
TARGET_DIR = r"F:\ARPA47-Dataset\ARPA47_Release_Split"

def chunk_list(lst, n):
    """Yield successive n-sized chunks from lst."""
    # We want exactly 3 chunks, so size is ceil(len(lst)/3)
    chunk_size = len(lst) // 3
    remainder = len(lst) % 3
    
    chunks = []
    start = 0
    for i in range(3):
        # distribute remainder to the first few chunks
        end = start + chunk_size + (1 if i < remainder else 0)
        chunks.append(lst[start:end])
        start = end
    return chunks

def split_zip_into_3(filepath, target_dir):
    filename = os.path.basename(filepath)
    basename = filename.replace(".zip", "")
    
    print(f"Splitting {filename} logically into 3 independent ZIPs...")
    
    with zipfile.ZipFile(filepath, 'r') as source_zip:
        parquet_files = sorted([f for f in source_zip.namelist() if f.endswith(".parquet")])
        
        chunks = chunk_list(parquet_files, 3)
        
        for part_num, chunk in enumerate(chunks, 1):
            part_filename = f"{basename}_part{part_num}.zip"
            part_filepath = os.path.join(target_dir, part_filename)
            
            with zipfile.ZipFile(part_filepath, 'w', zipfile.ZIP_DEFLATED) as target_zip:
                for pq_file in chunk:
                    # Read from source, write to target
                    data = source_zip.read(pq_file)
                    target_zip.writestr(pq_file, data)
            
            print(f"  -> Created {part_filename} with {len(chunk)} files.")

def main():
    if os.path.exists(TARGET_DIR):
        shutil.rmtree(TARGET_DIR)
    os.makedirs(TARGET_DIR)
    
    all_files = glob.glob(os.path.join(SOURCE_DIR, "*"))
    
    for filepath in all_files:
        if not os.path.isfile(filepath):
            continue
            
        filename = os.path.basename(filepath)
        
        if filename.endswith(".zip") and filename.startswith("arpa47_"):
            split_zip_into_3(filepath, TARGET_DIR)
        else:
            print(f"Copying {filename}...")
            shutil.copy2(filepath, os.path.join(TARGET_DIR, filename))
            
    print("\n[SUCCESS] Dataset logical splitting complete. Payload is ready in ARPA47_Release_Split!")

if __name__ == '__main__':
    main()
