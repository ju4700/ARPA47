import sys, os
sys.path.append('d:/Development/ARPA47/Sample_scripts/Dataset')
import build_dataset
build_dataset.INPUT_DIR = r'F:\ARPA47\zeek_archive'
build_dataset.OUTPUT_DIR = r'F:\ARPA47-Dataset\zeek_test'
build_dataset.LOG_TYPES = ['ssl']
build_dataset.OVERWRITE = True

# just do one day, single threaded
d = '2026-08-26'
folders = [f'F:\\ARPA47\\zeek_archive\\20260826_{h}' for h in range(20, 24)]
try:
    stats = build_dataset.process(d, 'ssl', folders)
    print(stats)
except Exception as e:
    import traceback
    traceback.print_exc()
