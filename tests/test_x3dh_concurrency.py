import multiprocessing
import tempfile
from pathlib import Path
from secxfer.keystore import generate_keypair, consume_prekey, get_unused_prekeys

def racer_process(keystore_dir_str, name, target_id, queue):
    try:
        consume_prekey(Path(keystore_dir_str), name, target_id)
        queue.put("SUCCESS")
    except FileNotFoundError:
        queue.put("BURNED")
    except Exception as e:
        queue.put(f"ERROR: {e}")

def test_atomic_prekey_consumption_concurrency():
    """
    Spawns multiple PROCESSES racing to consume the same pre-key.
    Validates that exactly ONE process succeeds and the rest fail safely.
    This proves the os.rename mechanism is TOCTOU-safe at the OS level,
    defeating the Python GIL.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        keystore_dir = Path(tmpdir)
        identity = generate_keypair(keystore_dir, "bob", 10)
        prekeys = get_unused_prekeys(keystore_dir, "bob")
        
        target_prekey = prekeys[0]
        target_id = target_prekey["id"]
        
        # Verify it exists
        pk_path = keystore_dir / "bob_prekeys" / f"{target_id}.key"
        assert pk_path.exists()
        
        queue = multiprocessing.Queue()
        processes = [
            multiprocessing.Process(
                target=racer_process, 
                args=(str(keystore_dir), "bob", target_id, queue)
            ) 
            for _ in range(20)
        ]
        
        for p in processes:
            p.start()
        for p in processes:
            p.join()
            
        results = []
        while not queue.empty():
            results.append(queue.get())
            
        successes = results.count("SUCCESS")
        burns = results.count("BURNED")
        
        assert successes == 1, f"Expected exactly 1 success, got {successes}. TOCTOU vulnerability present!"
        assert burns == 19, f"Expected 19 fail-safes, got {burns}."
        assert not pk_path.exists(), "Pre-key file should be gone after consumption."
