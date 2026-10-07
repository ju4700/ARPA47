import gzip
import glob
import os
import json
from collections import defaultdict
from multiprocessing import Pool

ARCHIVE_DIR = r"F:\ARPA47\zeek_archive"

def analyze_folder(folder):
    # returns: dict mapping log_type -> set of schema strings (comma separated fields)
    schemas = defaultdict(set)
    files = glob.glob(os.path.join(folder, "*.log.gz"))
    for f in files:
        basename = os.path.basename(f)
        # e.g., conn_20260826_120000.log.gz -> conn
        parts = basename.split('_')
        log_type = parts[0]
        # Some log types might have underscores in them, but zeek usually uses plain names or handles them well.
        # Let's extract log_type correctly by stripping the timestamp part.
        import re
        m = re.match(r'^([a-z0-9_]+)_\d{8}_\d{6}\.log\.gz$', basename)
        if m:
            log_type = m.group(1)
        else:
            log_type = basename.split('_')[0]
            
        try:
            with gzip.open(f, 'rt', errors='ignore') as z:
                for l in z:
                    if l.startswith('#fields'):
                        fields = l.strip().split('\t')[1:]
                        schemas[log_type].add(",".join(fields))
                        break
                    elif not l.startswith('#'):
                        break
        except Exception:
            pass
    
    # We can't return sets from multiprocessing if we want to JSON serialize later easily, 
    # but we can return lists.
    return {k: list(v) for k, v in schemas.items()}

if __name__ == '__main__':
    folders = [os.path.join(ARCHIVE_DIR, d) for d in os.listdir(ARCHIVE_DIR) if os.path.isdir(os.path.join(ARCHIVE_DIR, d))]
    
    global_schemas = defaultdict(set)
    log_types_seen = set()
    
    with Pool(os.cpu_count()) as pool:
        for res in pool.imap_unordered(analyze_folder, folders):
            for lt, schemas in res.items():
                log_types_seen.add(lt)
                for s in schemas:
                    global_schemas[lt].add(s)
                    
    # Generate report
    report = {}
    for lt in sorted(log_types_seen):
        report[lt] = []
        for s in global_schemas[lt]:
            fields = s.split(',')
            report[lt].append(fields)
            
    with open("dataset_architecture_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"Discovered {len(report)} unique log types.")
