import os, json
p = r'C:\Users\USER\.gemini\antigravity-ide\brain\f91cc1ff-8e2c-454f-b651-76ddf9faedb4\.system_generated\messages'
out = r'C:\Users\USER\.gemini\antigravity-ide\brain\98631cef-9cf8-4fa6-a29d-0f1b753c4b36\scratch\recovered_messages.md'
os.makedirs(os.path.dirname(out), exist_ok=True)
msgs = []
for fn in sorted(os.listdir(p)):
    if fn.endswith('.json'):
        try:
            content = json.load(open(os.path.join(p, fn), 'r', encoding='utf-8')).get('content', '')
            if type(content) is str:
                msgs.append(f'## Message {fn}\n\n{content}')
            elif type(content) is list:
                # Sometimes content is a list of blocks
                text = "\n".join([str(c) for c in content])
                msgs.append(f'## Message {fn}\n\n{text}')
        except Exception as e:
            msgs.append(f'Error reading {fn}: {e}')

with open(out, 'w', encoding='utf-8') as f:
    f.write('\n\n---\n\n'.join(msgs))
