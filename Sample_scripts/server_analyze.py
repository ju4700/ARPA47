import collections

tls = collections.Counter()
ciphers = collections.Counter()
curves = collections.Counter()
snis = collections.Counter()
n = 0

try:
    with open('/data/arpa/zeek_logs/ssl.log') as f:
        for line in f:
            if line.startswith('#'): continue
            p = line.strip().split('\t')
            if len(p) < 10: continue
            n += 1
            if p[6] != '-': tls[p[6]] += 1
            if p[7] != '-': ciphers[p[7]] += 1
            if p[8] != '-': curves[p[8]] += 1
            if p[9] != '-': snis[p[9]] += 1
except Exception as e:
    print(f"Error: {e}")

print(f'Total SSL/TLS Records: {n:,}')
print(f'\nTLS Version Breakdown:')
for k, v in tls.most_common(5):
    print(f'  {k}: {v:,} ({v/n*100:.1f}%)')

print(f'\nTop 10 SNIs (Destinations):')
for k, v in snis.most_common(10):
    print(f'  {k}: {v:,}')

print(f'\nTop Key Exchange Curves:')
for k, v in curves.most_common(5):
    print(f'  {k}: {v:,} ({v/n*100:.1f}%)')
