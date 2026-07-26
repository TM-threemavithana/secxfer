with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# We need to move _cmd_qr_show below the imports.
import re
match = re.search(r'(def _cmd_qr_show.*?)(?=from __future__)', content, flags=re.DOTALL)
if match:
    qr_code = match.group(1)
    content = content.replace(qr_code, '')
    # Insert it after the imports
    content = content.replace('import sys\n', 'import sys\n\n' + qr_code.strip() + '\n')
    with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
        f.write(content)
