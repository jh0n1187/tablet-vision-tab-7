"""Offline integrity and overwrite/traversal tests; no USB or real backup data."""
from pathlib import Path
import hashlib
import tempfile
import unittest
from restore_private_backup import safe_path, verify, restore


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = self.root / 'backup'
        self.backup.mkdir()
        self.source = self.backup / 'payload'
        self.source.write_bytes(b'known-original-firmware-fixture')
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.index = dict(source_workspace='C:\\original', entries=[
            dict(target=name, stored='payload', size=self.source.stat().st_size, sha256=self.digest)
            for name in ['backup/original.bin', 'analise-firmware/reference.bin']])

    def test_deduplicated_mapping_restores_and_verifies(self):
        self.assertEqual(verify(self.backup, self.index), 1)
        destination = self.root / 'project'
        self.assertEqual(restore(self.backup, destination, self.index), 2)
        self.assertEqual((destination / 'backup/original.bin').read_bytes(), self.source.read_bytes())
        self.assertEqual(restore(self.backup, destination, self.index), 0)

    def test_tampered_payload_is_rejected(self):
        self.source.write_bytes(b'corrupted')
        with self.assertRaises(ValueError):
            verify(self.backup, self.index)

    def test_existing_difference_prevents_all_writes(self):
        destination = self.root / 'project'
        existing = destination / 'analise-firmware/reference.bin'
        existing.parent.mkdir(parents=True)
        existing.write_bytes(b'pre-existing unrelated work')
        with self.assertRaises(FileExistsError):
            restore(self.backup, destination, self.index)
        self.assertFalse((destination / 'backup/original.bin').exists())
        self.assertEqual(existing.read_bytes(), b'pre-existing unrelated work')

    def test_unsafe_paths_rejected(self):
        for name in ['../escape', '/absolute', 'C:/outside', 'folder\\outside']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_path(self.root, name)


if __name__ == '__main__':
    unittest.main()
