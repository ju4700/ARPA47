import os
import subprocess
import glob
from concurrent.futures import ThreadPoolExecutor

SOURCE_DIR = "/mnt/f/ARPA47/netflow/2026"
OUTPUT_DIR = "/mnt/g/ARPA47_NetFlow_Anonymized"
# 32-byte key for CryptoPAn anonymization (simulating a random salt that we will destroy later)
CRYPTO_KEY = "3a9c7d42e61b9a2c3d5f8e7a4b1c2d3e"
# Filter to exclude TZSP (37008), Syslog (514), and NetFlow collection itself (2055)
FILTER_EXPR = "not port 37008 and not port 2055 and not port 514"

def process_file(input_file):
    rel_path = os.path.relpath(input_file, SOURCE_DIR)
    output_file = os.path.join(OUTPUT_DIR, rel_path)
    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)
    
    # Skip if already exists
    if os.path.exists(output_file):
        return f"Skipped {rel_path}"

    tmp_file = output_file + ".tmp"
    
    # 1. Filter out the measurement traffic and write to tmp file (WITH COMPRESSION -z)
    cmd_filter = ["nfdump", "-z", "-r", input_file, "-w", tmp_file, FILTER_EXPR]
    subprocess.run(cmd_filter, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 2. Anonymize the tmp file in-place using CryptoPAn
    cmd_anon = ["nfanon", "-K", CRYPTO_KEY, "-r", tmp_file]
    subprocess.run(cmd_anon, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 3. Rename to final file
    os.rename(tmp_file, output_file)
    return f"Processed {rel_path}"

def main():
    print(f"Starting NetFlow anonymization and filtering pipeline...")
    files_to_process = []
    
    for root, dirs, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.startswith("nfcapd."):
                files_to_process.append(os.path.join(root, file))
                
    print(f"Found {len(files_to_process)} nfcapd files to process.")
    
    # Process files in parallel to speed things up
    with ThreadPoolExecutor(max_workers=8) as executor:
        for result in executor.map(process_file, files_to_process):
            # Print every 100th file to show progress without spamming
            if "Processed" in result and int(result[-4:]) % 100 == 0:
                print(result)
                
    print("All files processed and anonymized! Ready for packaging.")

if __name__ == "__main__":
    main()
