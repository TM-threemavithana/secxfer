import subprocess
import re
import os
import shutil

if os.path.exists('tests/test_ux'):
    shutil.rmtree('tests/test_ux')

os.makedirs('tests/test_ux/alice')
os.makedirs('tests/test_ux/bob')

print("1. Generating Alice keys")
subprocess.run(['python', 'src/secxfer/cli.py', 'keygen', '--dir', 'tests/test_ux/alice', '--name', 'alice'])
subprocess.run(['python', 'src/secxfer/cli.py', 'register', '--identity', 'tests/test_ux/alice/alice.key', '--server', 'http://127.0.0.1:8555'])

print("2. Generating Bob keys")
subprocess.run(['python', 'src/secxfer/cli.py', 'keygen', '--dir', 'tests/test_ux/bob', '--name', 'bob'])
subprocess.run(['python', 'src/secxfer/cli.py', 'register', '--identity', 'tests/test_ux/bob/bob.key', '--server', 'http://127.0.0.1:8555'])

# Get IDs
out_alice = subprocess.check_output(['python', 'src/secxfer/cli.py', 'show-id', '--identity', 'tests/test_ux/alice/alice.key'], text=True)
alice_id = re.search(r'Key ID\s+:\s+([a-f0-9]+)', out_alice).group(1)

out_bob = subprocess.check_output(['python', 'src/secxfer/cli.py', 'show-id', '--identity', 'tests/test_ux/bob/bob.key'], text=True)
bob_id = re.search(r'Key ID\s+:\s+([a-f0-9]+)', out_bob).group(1)

print("Alice ID:", alice_id)
print("Bob ID:", bob_id)

print("3. Cross-pinning")
subprocess.run(['python', 'src/secxfer/cli.py', 'pin', '--key-id', alice_id, '--name', 'alice', '--keystore', 'tests/test_ux/bob/keystore', '--server', 'http://127.0.0.1:8555'])
subprocess.run(['python', 'src/secxfer/cli.py', 'pin', '--key-id', bob_id, '--name', 'bob', '--keystore', 'tests/test_ux/alice/keystore', '--server', 'http://127.0.0.1:8555'])

print("4. Bob sends to Alice")
with open('tests/test_ux/bob/secret.txt', 'w') as f:
    f.write("Super secret message from Bob to Alice via V2")
subprocess.run(['python', 'src/secxfer/cli.py', 'send', 'tests/test_ux/bob/secret.txt', '--identity', 'tests/test_ux/bob/bob.key', '--to', 'alice', '--server', 'http://127.0.0.1:8555', '--keystore', 'tests/test_ux/bob/keystore', '--out', 'tests/test_ux/bob/secret.txt.enc'])

print("5. Alice receives")
# Note: In receive we no longer pass --name because we removed it in the CLI!
subprocess.run(['python', 'src/secxfer/cli.py', 'receive', 'tests/test_ux/alice/decrypted.txt', '--identity', 'tests/test_ux/alice/alice.key', '--keystore', 'tests/test_ux/alice/keystore', '--in', 'tests/test_ux/bob/secret.txt.enc'])

print("6. Verify Output")
with open('tests/test_ux/alice/decrypted.txt', 'r') as f:
    print("Decrypted Content:", f.read())
