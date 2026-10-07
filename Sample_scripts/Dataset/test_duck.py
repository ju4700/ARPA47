import duckdb
print(duckdb.sql("SELECT server_name, count(*) FROM 'F:/ARPA47-Dataset/zeek_test/ssl/ssl_2026-08-26.parquet' GROUP BY 1 ORDER BY 2 DESC LIMIT 10").df())
