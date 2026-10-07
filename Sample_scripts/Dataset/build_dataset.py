import os
import gzip
import glob
import hmac
import hashlib
import ipaddress
import logging
import secrets
import csv
import re
import tldextract
from collections import defaultdict
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, as_completed

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

# ---------------- CONFIG ----------------
INPUT_DIR = r'F:\ARPA47\zeek_archive'
OUTPUT_DIR = r'F:\ARPA47-Dataset\zeek_v2'
KEY_FILE = r'F:\ARPA47-secrets\anon.key'      # keep OUTSIDE the published dataset
LOG_TYPES = ['ssl', 'conn', 'dns', 'quic', 'http', 'weird']
SUBSCRIBER_NET = ipaddress.ip_network('10.60.1.0/24')
IP_COLUMNS = ['id.orig_h', 'id.resp_h']       # anonymize both directions
CHUNK_ROWS = 500_000                          # bounds RAM per file
WORKERS = max(1, (os.cpu_count() or 2) - 1)
COMPRESSION = 'zstd'
OVERWRITE = False                             # False = resume (skip finished outputs)
# ----------------------------------------

log = logging.getLogger('zeekbuild')


# ---------- anonymization ----------
def load_or_create_key(path=KEY_FILE):
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = secrets.token_bytes(32)
    with open(path, 'wb') as f:
        f.write(key)
    return key


_KEY = None


def _key():
    global _KEY
    if _KEY is None:
        _KEY = load_or_create_key()
    return _KEY


@lru_cache(maxsize=None)
def anon_ip(ip):
    if ip is None:
        return None
    try:
        if ipaddress.ip_address(ip) in SUBSCRIBER_NET:
            return 'sub_' + hmac.new(_key(), ip.encode(), hashlib.sha256).hexdigest()[:12]
    except ValueError:
        pass
    return ip


def anon_column(arr, func=anon_ip):
    uniq = pc.unique(arr)
    mapped = pa.array([func(v) for v in uniq.to_pylist()], pa.string())
    return mapped.take(pc.index_in(arr, value_set=uniq))


_ext = tldextract.TLDExtract(suffix_list_urls=())

@lru_cache(maxsize=200000)
def anon_domain(d):
    if not d or not isinstance(d, str):
        return d
    try:
        ipaddress.ip_address(d)
        return anon_ip(d)
    except ValueError:
        pass
    e = _ext(d)
    return f'*.{e.registered_domain}' if e.subdomain and e.registered_domain else d


# ---------- Zeek parsing ----------
def zeek_to_arrow_type(t):
    if t.startswith(('set[', 'vector[')):
        return pa.list_(pa.string())
    return {
        'time': pa.timestamp('us', tz='UTC'),
        'interval': pa.float64(),
        'count': pa.int64(),
        'int': pa.int64(),
        'port': pa.int32(),
        'double': pa.float64(),
        'bool': pa.bool_(),
    }.get(t, pa.string())


def build_column(values, ztype, meta):
    arr = pa.array(values, pa.string())
    nulls = pa.array([meta['unset'], meta['empty']], pa.string())
    arr = pc.if_else(pc.is_in(arr, value_set=nulls), pa.scalar(None, pa.string()), arr)
    target = zeek_to_arrow_type(ztype)
    if pa.types.is_list(target):
        return pc.split_pattern(arr, meta['set_sep'])
    if pa.types.is_timestamp(target):
        us = pc.multiply(arr.cast(pa.float64()), 1_000_000).cast(pa.int64())
        return us.cast(target)
    if pa.types.is_boolean(target):
        return pc.equal(arr, 'T')
    if target == pa.string():
        return arr
    return arr.cast(target)


def rows_to_table(fields, types, meta, rows):
    cols = list(zip(*rows)) if rows else [[] for _ in fields]
    arrays = [build_column(list(c), t, meta) for c, t in zip(cols, types)]
    table = pa.Table.from_arrays(arrays, names=fields)
    
    # Drop MAC addresses and cleartext credentials/resources
    drop_cols = [c for c in table.column_names if c in {'orig_l2_addr', 'resp_l2_addr', 'mac', 'username', 'password', 'uri', 'referrer', 'addl'}]
    if drop_cols:
        table = table.drop_columns(drop_cols)
        
    for name in IP_COLUMNS:
        if name in table.column_names:
            i = table.column_names.index(name)
            table = table.set_column(i, name, anon_column(table.column(name).combine_chunks(), anon_ip))
            
    for name in ['server_name', 'query', 'host']:
        if name in table.column_names:
            i = table.column_names.index(name)
            table = table.set_column(i, name, anon_column(table.column(name).combine_chunks(), anon_domain))
            
    return table


def read_zeek_gz(path, stats, schema_cache):
    meta = schema_cache.get('meta', {'set_sep': ',', 'empty': '(empty)', 'unset': '-'})
    fields = schema_cache.get('fields')
    types = schema_cache.get('types')
    rows = []
    try:
        with gzip.open(path, 'rt', encoding='utf-8', errors='replace', newline='') as f:
            for line in f:
                if len(line) == 0: continue
                if line[0] == '#':
                    k, _, v = line.rstrip('\n').partition('\t')
                    if k == '#fields':
                        fields = v.split('\t')
                        schema_cache['fields'] = fields
                    elif k == '#types':
                        types = v.split('\t')
                        schema_cache['types'] = types
                    elif k == '#set_separator':
                        meta['set_sep'] = v
                    elif k == '#empty_field':
                        meta['empty'] = v
                    elif k == '#unset_field':
                        meta['unset'] = v
                    schema_cache['meta'] = meta
                    continue
                if not fields or not types:
                    # Skip lines if we haven't seen a header yet across any files
                    continue
                
                # Check for null byte padding which can happen on crashes
                if line.startswith('\x00'):
                    continue
                
                parts = line.rstrip('\n').split('\t')
                if len(parts) != len(fields):
                    stats['bad_lines'] += 1
                    continue
                rows.append(parts)
                if len(rows) >= CHUNK_ROWS:
                    yield rows_to_table(fields, types, meta, rows)
                    rows = []
    except (EOFError, OSError) as e:
        stats['bad_files'] += 1
        log.warning('Truncated/corrupt %s: %s', path, e)
    if rows and fields and types:
        yield rows_to_table(fields, types, meta, rows)


def align(table, schema):
    arrays = []
    for field in schema:
        if field.name in table.column_names:
            col = table.column(field.name)
            if col.type != field.type:
                col = col.cast(field.type)
            arrays.append(col)
        else:
            arrays.append(pa.nulls(table.num_rows, field.type))
    return pa.Table.from_arrays(arrays, schema=schema)


# ---------- per-day / per-type job ----------
def process(date_str, log_type, folders, global_schema=None):
    out = os.path.join(OUTPUT_DIR, log_type, f'{log_type}_{date_str}.parquet')
    stats = {'date': date_str, 'log': log_type, 'rows': 0, 'bad_lines': 0, 'bad_files': 0, 'files': 0}
    if os.path.exists(out) and not OVERWRITE:
        stats['rows'] = pq.ParquetFile(out).metadata.num_rows
        return stats

    pat = re.compile(rf'^{log_type}_\d')
    files = sorted(f for d in folders for f in glob.glob(os.path.join(d, f'{log_type}_*.log.gz')) if pat.match(os.path.basename(f)))
    tmp = out + '.tmp'
    writer = None
    schema_cache = dict(global_schema) if global_schema else {}
    try:
        for fp in files:
            stats['files'] += 1
            for table in read_zeek_gz(fp, stats, schema_cache):
                if writer is None:
                    writer = pq.ParquetWriter(tmp, table.schema, compression=COMPRESSION)
                writer.write_table(align(table, writer.schema))
                stats['rows'] += table.num_rows
    finally:
        if writer:
            writer.close()
    if writer:
        os.replace(tmp, out)
    return stats


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    load_or_create_key()
    for lt in LOG_TYPES:
        os.makedirs(os.path.join(OUTPUT_DIR, lt), exist_ok=True)

    date_to_folders = defaultdict(list)
    for folder in sorted(glob.glob(os.path.join(INPUT_DIR, '*_*'))):
        if not os.path.isdir(folder):
            continue
        d = os.path.basename(folder).split('_')[0]
        if len(d) == 8 and d.isdigit():
            date_to_folders[f'{d[:4]}-{d[4:6]}-{d[6:]}'].append(folder)

    # Extract schemas chronologically to handle Zeek schema evolution
    schemas_by_day = {lt: {} for lt in LOG_TYPES}
    current_schema = {lt: {'meta': {'set_sep': ',', 'empty': '(empty)', 'unset': '-'}} for lt in LOG_TYPES}
    
    # Chronological pass
    for folder in sorted(glob.glob(os.path.join(INPUT_DIR, '*_*'))):
        d = os.path.basename(folder).split('_')[0]
        if not (len(d) == 8 and d.isdigit()): continue
        date_str = f'{d[:4]}-{d[4:6]}-{d[6:]}'
        
        for lt in LOG_TYPES:
            files = sorted(glob.glob(os.path.join(folder, f'{lt}_*.log.gz')))
            for f in files:
                try:
                    with gzip.open(f, 'rt', errors='ignore') as z:
                        for l in z:
                            if l.startswith('#fields'): current_schema[lt]['fields'] = l.strip().split('\t')[1:]
                            elif l.startswith('#types'): current_schema[lt]['types'] = l.strip().split('\t')[1:]
                            elif not l.startswith('#'): break
                except Exception: pass
            
            # Store whatever the current schema is for this day
            if 'fields' in current_schema[lt] and 'types' in current_schema[lt]:
                schemas_by_day[lt][date_str] = dict(current_schema[lt])

    jobs = [(d, lt, fs, schemas_by_day[lt].get(d)) for d, fs in sorted(date_to_folders.items()) for lt in LOG_TYPES]
    log.info('%d jobs (%d days x %d log types), %d workers', len(jobs), len(date_to_folders), len(LOG_TYPES), WORKERS)

    results = []
    with ProcessPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(process, *j): j for j in jobs}
        for fut in as_completed(futs):
            d, lt, _, _ = futs[fut]
            try:
                r = fut.result()
                results.append(r)
                log.info('%s %s rows=%d bad_lines=%d bad_files=%d', d, lt, r['rows'], r['bad_lines'], r['bad_files'])
            except Exception:
                log.exception('FAILED %s %s', d, lt)

    manifest = os.path.join(OUTPUT_DIR, 'manifest.csv')
    with open(manifest, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['date', 'log', 'files', 'rows', 'bad_lines', 'bad_files'])
        w.writeheader()
        w.writerows(sorted(results, key=lambda r: (r['date'], r['log'])))
    log.info('Dataset build complete. Manifest: %s', manifest)


if __name__ == '__main__':
    main()
