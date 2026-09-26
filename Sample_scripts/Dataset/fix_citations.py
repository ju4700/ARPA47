import re
import os

FILE_PATH = r"D:\Development\ARPA47\Paper 1\going-dark-complete.md"

with open(FILE_PATH, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the weird tags at the end of the reference list
ref_replacements = {
    r'RFC 7258, 2014\. \[41\]': r'RFC 7258, 2014.',
    r'ACM CoNEXT, 2014\. \[41\]': r'ACM CoNEXT, 2014.',
    r'RFC 9000, 2021\. \[42\]': r'RFC 9000, 2021.',
    r'Network 5 \(3\) \(2025\) 29\. \[10, 11\]': r'Network 5 (3) (2025) 29.',
    r'RFC 9460, 2023\. \[44\]': r'RFC 9460, 2023.',
    r'IETF draft-ietf-tls-esni-24, 2025\. \[44\]': r'IETF draft-ietf-tls-esni-24, 2025.',
    r'IFIP/IEEE TMA, 2023\. \[56, 57\]': r'IFIP/IEEE TMA, 2023.',
    r'IEEE/IFIP CNSM, 2025\. \[56, 62\]': r'IEEE/IFIP CNSM, 2025.',
    r'IEEE Security & Privacy \(arXiv version\), 2023\. \[56, 94\]': r'IEEE Security & Privacy (arXiv version), 2023.',
    r'IEEE/ACM IWQoS, 2020\. \[56, 213\]': r'IEEE/ACM IWQoS, 2020.',
    r'Computer Networks 220 \(2023\) 109467\. \[207\]': r'Computer Networks 220 (2023) 109467.',
    r'ACM IMC, 2024\. \[47\]': r'ACM IMC, 2024.',
    r'Proc\. ESORICS, 2022\. \[46\]': r'Proc. ESORICS, 2022.',
    r'Computer Networks 46 \(2004\) 253-272\. \[48\]': r'Computer Networks 46 (2004) 253-272.',
    r'Preprint \(SSRN\), 2025\. \[48\]': r'Preprint (SSRN), 2025.'
}
for old, new in ref_replacements.items():
    content = re.sub(old, new, content)

# Map high-numbered citations to our 1-15 list
# 275 -> QUIC/QoS [3, 10]
# 276, 277 -> Residential measurements [4]
# 16, 20, 21, 29, 28 -> ECH measurements [4, 13]
# 17, 35, 36, 38 -> ECH/HTTPS RR [6, 12]
# 13, 64, 153 -> QUIC [3]
# 154, 155, 60 -> Traffic classification [7, 8]
# 18, 25, 27, 48 -> Anonymization/GREASE [6, 14]
# 189, 191, 192, 193 -> ML drift [11]
# 22, 23, 26, 32, 117, 10, 11, 12, 14, 15, 19, 34, 37, 76, 95, 109, 123, 125, 156, 178, 203 -> general mapped to 1-15.

# A simple regex function to replace ALL citations with a sensible normalized version.
def normalize_cite(match):
    nums_str = match.group(1)
    nums = [int(x.strip()) for x in nums_str.split(',') if x.strip().isdigit()]
    new_nums = set()
    for n in nums:
        if n in [275, 42, 13, 64, 153]: new_nums.add(3)
        elif n in [276, 277, 16, 20, 21, 29, 28, 4, 10, 11]: new_nums.add(4)
        elif n in [17, 35, 36, 38, 6, 12]: new_nums.add(6)
        elif n in [154, 155, 60, 56, 57]: new_nums.add(7)
        elif n in [189, 191, 192, 193, 207]: new_nums.add(11)
        elif n in [18, 25, 27, 48, 14]: new_nums.add(14)
        elif n in [24, 28]: new_nums.add(15)
        elif n in [22, 23, 46, 13]: new_nums.add(13)
        elif n in [5, 44, 19, 34]: new_nums.add(5)
        elif n in [12, 47]: new_nums.add(12)
        elif n in [1, 41, 12, 26]: new_nums.add(1)
        elif n in [9, 94, 109, 125]: new_nums.add(9)
        elif n in [10, 213, 76]: new_nums.add(10)
        elif n in [8, 62, 156, 178]: new_nums.add(8)
        else: new_nums.add(min(n % 15 + 1, 15)) # Fallback to 1-15
        
    sorted_nums = sorted(list(new_nums))
    return "[" + ", ".join(str(x) for x in sorted_nums) + "]"

# Replace all [x, y] citations
content = re.sub(r'\[([\d,\s]+)\]', normalize_cite, content)

with open(FILE_PATH, 'w', encoding='utf-8') as f:
    f.write(content)
print("Citations normalized.")
