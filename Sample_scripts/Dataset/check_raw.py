import gzip, glob, sys
day, lt = sys.argv[1:3]
files = [f for d in glob.glob(f"F:/ARPA47/zeek_archive/{day.replace('-','')}_*") for f in glob.glob(f"{d}/{lt}_*.log.gz")]
for f in files:
    c = 0
    try:
        for l in gzip.open(f, 'rt', errors='replace'): 
            if len(l) > 0 and l[0] != '#': c += 1
    except (EOFError, OSError): pass
    print(f"{f}: {c}")
