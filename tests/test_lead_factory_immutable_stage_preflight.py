import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory.immutable_stage_preflight import (
    ImmutableStagePreflightError,
    read_immutable_stage_safety,
)


class ImmutableStagePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "canonical.sqlite3"
        con = sqlite3.connect(self.path)
        con.executescript(
            """
            CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES('schema_version','13');
            INSERT INTO schema_meta VALUES('external_writers_enabled','0');
            CREATE TABLE crm_outbox(state TEXT NOT NULL);
            """
        )
        con.commit()
        con.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_reads_schema13_without_writing_or_creating_sidecars(self):
        before = self.path.read_bytes()
        snapshot = read_immutable_stage_safety(self.path)
        self.assertTrue(snapshot.ok)
        self.assertEqual(snapshot.schema_version, 13)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(Path(str(self.path) + "-wal").exists())
        self.assertFalse(Path(str(self.path) + "-shm").exists())

    def test_pending_outbox_fails_safety_without_mutation(self):
        con = sqlite3.connect(self.path)
        con.execute("INSERT INTO crm_outbox VALUES('PENDING')")
        con.commit()
        con.close()
        snapshot = read_immutable_stage_safety(self.path)
        self.assertFalse(snapshot.ok)
        self.assertEqual(snapshot.pending_crm_operations, 1)

    def test_missing_contract_fails_closed(self):
        broken = Path(self.temp.name) / "broken.sqlite3"
        sqlite3.connect(broken).close()
        with self.assertRaises(ImmutableStagePreflightError):
            read_immutable_stage_safety(broken)
