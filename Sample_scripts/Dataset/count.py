import gzip, glob, os
from multiprocessing import Pool

def analyze_conn(f):
    valid = 0
    nulls = 0
    try:
        with gzip.open(f, 'rt', encoding='utf-8', errors='ignore') as f:
            for l in f:
                if l.startswith('\x00'): nulls += 1
                elif not l.startswith('#') and len(l) > 1: valid += 1
    except Exception: pass
    return valid, nulls

if __name__ == '__main__':
    files = glob.glob('F:/ARPA47/zeek_archive/*_*/conn*.log.gz')
    with Pool(os.cpu_count()) as p:
        results = p.map(analyze_conn, files)
    
    total_valid = sum(r[0] for r in results)
    total_nulls = sum(r[1] for r in results)
    print(f"Total valid conn rows: {total_valid:,}")
    print(f"Total null lines: {total_nulls:,}")
    print(f"Total lines seen by simple parser: {total_valid + total_nulls:,}")
