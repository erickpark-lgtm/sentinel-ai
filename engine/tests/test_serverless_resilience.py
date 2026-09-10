"""
Unit tests for SentinelAI Serverless State Persistence, Log Integrity Lambda,
and API Rate-Limiting Exponential Backoff.
"""

import unittest
import json
import hashlib
from engine.core.retry_utils import with_exponential_backoff
from engine.core.heartbeat_watchdog import HeartbeatWatchdog
from engine.core.verify_log_integrity import lambda_handler, verify_chain_continuity

class MockTransactionalDynamoClient:
    def __init__(self):
        self.transact_calls = []

    def transact_write_items(self, TransactItems):
        self.transact_calls.append(TransactItems)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

class MockDynamoTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        pk = Key.get("pk")
        sk = Key.get("sk")
        item = self.items.get((pk, sk))
        return {"Item": item} if item else {}

    def put_item(self, Item):
        pk = Item.get("pk")
        sk = Item.get("sk")
        self.items[(pk, sk)] = Item

class MockDynamoResource:
    def __init__(self):
        self.table = MockDynamoTable()

    def Table(self, name):
        return self.table

class TestServerlessResilience(unittest.TestCase):

    def test_exponential_backoff_rate_limit(self):
        call_count = 0

        @with_exponential_backoff(max_retries=3, base_delay=0.01, max_delay=0.05)
        def flaky_api():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return (429, {"message": "API rate limit exceeded"})
            return (200, {"status": "ok"})

        status, data = flaky_api()
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(call_count, 3)

    def test_dynamodb_serverless_state_persistence(self):
        mock_dyn = MockDynamoResource()
        watchdog = HeartbeatWatchdog(
            ledger_path="temp_test_ledger.jsonl",
            dynamodb_table="sentinel_audit_ledger_test",
            dynamodb_client=mock_dyn
        )

        # Record first block in serverless environment
        b0 = watchdog.record_heartbeat("org/core-repo", checks_executed=5)
        self.assertEqual(b0["block_index"], 0)
        self.assertEqual(b0["prev_hash"], HeartbeatWatchdog.GENESIS_HASH)

        # Simulate Lambda container recycle: create brand new watchdog instance
        # It must retrieve H_{0} from DynamoDB to produce block_index 1
        watchdog_recycled = HeartbeatWatchdog(
            ledger_path="temp_different_ledger.jsonl",
            dynamodb_table="sentinel_audit_ledger_test",
            dynamodb_client=mock_dyn
        )

        b1 = watchdog_recycled.record_heartbeat("org/core-repo", checks_executed=5)
        self.assertEqual(b1["block_index"], 1)
        self.assertEqual(b1["prev_hash"], b0["block_hash"])

        # Clean up temporary test files if created
        import os
        for fn in ["temp_test_ledger.jsonl", "temp_different_ledger.jsonl"]:
            if os.path.exists(fn):
                os.remove(fn)

    def test_dynamodb_transact_write_items_execution(self):
        mock_client = MockTransactionalDynamoClient()
        watchdog = HeartbeatWatchdog(
            ledger_path="temp_transact_ledger.jsonl",
            dynamodb_table="sentinel_audit_ledger_prod",
            dynamodb_client=mock_client
        )
        b0 = watchdog.record_heartbeat("org/fintech-repo", checks_executed=5)
        self.assertEqual(len(mock_client.transact_calls), 1)
        items = mock_client.transact_calls[0]
        self.assertEqual(len(items), 2)
        self.assertIn("ConditionExpression", items[0]["Put"])
        self.assertIn("ConditionExpression", items[1]["Put"])
        self.assertEqual(items[0]["Put"]["Item"]["sk"]["S"], "BLOCK#0000000000")
        self.assertEqual(items[1]["Put"]["Item"]["sk"]["S"], "LATEST")

        import os
        if os.path.exists("temp_transact_ledger.jsonl"):
            os.remove("temp_transact_ledger.jsonl")

    def test_verify_chain_continuity_valid_and_tampered(self):
        watchdog = HeartbeatWatchdog(ledger_path="temp_continuity.jsonl")
        b0 = watchdog.record_heartbeat("org/test-repo", checks_executed=5)
        b1 = watchdog.record_heartbeat("org/test-repo", checks_executed=5)
        b2 = watchdog.record_heartbeat("org/test-repo", checks_executed=5)

        # 1. Valid chain test
        valid, errors = verify_chain_continuity([b0, b1, b2])
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

        # 2. Chain fork / deleted intermediate block test (Simulate block 1 missing)
        fork_valid, fork_errors = verify_chain_continuity([b0, b2])
        self.assertFalse(fork_valid)
        self.assertTrue(any("Index sequence mismatch" in err or "Chain break" in err for err in fork_errors))

        # 3. Payload tampering test
        tampered_b1 = dict(b1)
        tampered_b1["checks_executed"] = 999
        t_valid, t_errors = verify_chain_continuity([b0, tampered_b1, b2])
        self.assertFalse(t_valid)
        self.assertTrue(any("Cryptographic payload tampering" in err for err in t_errors))

        import os
        if os.path.exists("temp_continuity.jsonl"):
            os.remove("temp_continuity.jsonl")

    def test_verify_log_integrity_handler_clean_event(self):
        # Verify lambda handler produces clean output when records list is empty
        event = {"Records": []}
        res = lambda_handler(event, None)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertEqual(body["status"], "PASS")

if __name__ == "__main__":
    unittest.main()
