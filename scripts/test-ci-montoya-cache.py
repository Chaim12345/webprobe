#!/usr/bin/env python3
"""Offline tests execute the exact Montoya fetch helper with a fake curl."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / '.github/actions/montoya-api/fetch.sh'
PAYLOAD = b'pinned test fixture, not the real API'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FetchTests(unittest.TestCase):
    def exercise(self, initial=None, mode='good', expected_ok=True, downloads=0):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'montoya-api.jar'
            if initial is not None:
                target.write_bytes(initial)
            fake = root / 'curl'
            fake.write_text('''#!/usr/bin/env python3
import os,sys,pathlib
root=pathlib.Path(os.environ['FIXTURE_ROOT'])
with (root/'calls').open('a') as f: f.write('download\\n')
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1])
mode=os.environ['FIXTURE_MODE']
out.write_bytes((root/'payload').read_bytes() if mode=='good' else b'truncated')
if mode=='fail': sys.exit(22)
''')
            fake.chmod(0o700)
            (root / 'payload').write_bytes(PAYLOAD)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       FIXTURE_ROOT=str(root), FIXTURE_MODE=mode)
            # A failed helper must stop the consuming test command.
            result = subprocess.run(['bash', '-e', '-c',
                                     'bash "$1" "$2" "$3" "$4"; touch "$5"',
                                     'fixture', str(HELPER), 'https://example.invalid/pin.jar',
                                     DIGEST, str(target), str(root / 'tests-ran')],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, expected_ok, result.stdout + result.stderr)
            self.assertEqual((root / 'tests-ran').exists(), expected_ok)
            calls = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
            self.assertEqual(len(calls), downloads)
            self.assertFalse(list(root.glob('*.download.*')))
            if expected_ok:
                self.assertEqual(target.read_bytes(), PAYLOAD)
                self.assertIn('OK', result.stdout)  # Checksum actually executed, including hits.
            elif initial is None:
                self.assertFalse(target.exists())

    def test_valid_hit_hashes_without_download(self):
        self.exercise(PAYLOAD)

    def test_miss_downloads_once_and_verifies(self):
        self.exercise(downloads=1)

    def test_corrupt_hit_fails_without_download_or_tests(self):
        self.exercise(b'corrupt', expected_ok=False)

    def test_failed_partial_download_leaves_no_final_jar(self):
        self.exercise(mode='fail', expected_ok=False, downloads=1)

    def test_wrong_hash_download_leaves_no_final_jar(self):
        self.exercise(mode='wrong', expected_ok=False, downloads=1)


if __name__ == '__main__':
    unittest.main()
