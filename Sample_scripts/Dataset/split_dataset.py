import os
import glob
import shutil
import math

SOURCE_DIR = r"F:\ARPA47-Dataset\ARPA47_Release"
TARGET_DIR = r"F:\ARPA47-Dataset\ARPA47_Release_Split"

def split_file_into_3(filepath, target_dir):
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)
    
    # Calculate chunk size to exactly create 3 files (ceiling division)
    chunk_size = math.ceil(file_size / 3)
    
    print(f"Splitting {filename} ({file_size / (1024*1024):.2f} MB) into 3 parts of ~{chunk_size / (1024*1024):.2f} MB...")
    
    with open(filepath, 'rb') as f:
        part_num = 1
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            part_filename = f"{filename}.{part_num:03d}"
            part_filepath = os.path.join(target_dir, part_filename)
            
            with open(part_filepath, 'wb') as part_f:
                part_f.write(chunk)
                
            print(f"  -> Created {part_filename}")
            part_num += 1

def main():
    if os.path.exists(TARGET_DIR):
        shutil.rmtree(TARGET_DIR)
    os.makedirs(TARGET_DIR)
    
    all_files = glob.glob(os.path.join(SOURCE_DIR, "*"))
    
    for filepath in all_files:
        if not os.path.isfile(filepath):
            continue
            
        filename = os.path.basename(filepath)
        
        # Split only the primary .zip data files
        if filename.endswith(".zip") and filename.startswith("arpa47_"):
            split_file_into_3(filepath, TARGET_DIR)
        else:
            # Copy non-zip files directly (e.g., manifest.csv, LICENSE, statistics.zip)
            print(f"Copying {filename}...")
            shutil.copy2(filepath, os.path.join(TARGET_DIR, filename))
            
    print("\n[SUCCESS] Dataset splitting complete. Payload is ready in ARPA47_Release_Split!")

if __name__ == '__main__':
    main()
