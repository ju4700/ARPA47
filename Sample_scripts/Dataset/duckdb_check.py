import duckdb
P = 'F:/ARPA47-Dataset/zeek'
q = lambda s: print(duckdb.sql(s).df())
print('--- CONN BREAKDOWN ---')
q(f"select proto, service, conn_state, count(*) n from '{P}/conn/**/*.parquet' group by all order by n desc limit 10")
print('--- SSL MISSING VERSION ---')
q(f"select version is null as no_version, count(*) from '{P}/ssl/**/*.parquet' group by all")
print('--- DNS MISSING QTYPE ---')
q(f"select qtype_name is null as no_qtype, count(*) from '{P}/dns/**/*.parquet' group by all")
print('--- QUIC MISSING SNI ---')
q(f"select server_name is null as no_sni, version, count(*) from '{P}/quic/**/*.parquet' group by all order by 3 desc limit 10")
