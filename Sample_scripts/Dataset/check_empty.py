import pandas as pd
import numpy as np

files = [
    r'f:\ARPA47-Dataset\zeek\ssl\ssl_2026-09-05.parquet',
    r'f:\ARPA47-Dataset\zeek\conn\conn_2026-09-12.parquet',
    r'f:\ARPA47-Dataset\zeek\http\http_2026-08-30.parquet'
]

for f in files:
    try:
        df = pd.read_parquet(f)
        import os
        print(f'\n--- Analyzing {os.path.basename(f)} ---')
        print(f'Shape: {df.shape}')
        
        # Count actual NaNs and Zeek empty strings ('-', '')
        empty_mask = df.isna() | (df == '-') | (df == '')
        empty_counts = empty_mask.sum()
        
        print('Columns with >50% empty cells (indicated by - or NaN):')
        for col, count in empty_counts.items():
            pct = (count / len(df)) * 100
            if pct > 50:
                print(f'  {col}: {pct:.1f}% empty ({count} rows)')
    except Exception as e:
        print(f'Error reading {f}: {e}')
