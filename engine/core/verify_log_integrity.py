"""
SentinelAI Serverless Log Integrity Verifier (AWS Lambda)
Triggered by S3 ObjectCreated events to verify cryptographic SHA-256 hash chains,
detect silent failures, and tag compliant audit packages under AICPA AT-C 205.
"""

import json
import os
import hashlib
import urllib.parse
from typing import Dict, Any

try:
    import boto3
except ImportError:
    boto3 = None

def verify_chain_continuity(blocks: list[Dict[str, Any]]) -> tuple[bool, list[str]]:
    """
    Validates cryptographic chain continuity across sorted blocks (AICPA AT-C 205).
    Enforces sequential indexing, unbroken prev_hash Merkle links, and payload integrity.
    """
    if not blocks:
        return False, ["No blocks available for verification."]

    errors = []
    # Sort blocks strictly by block_index ascending
    sorted_blocks = sorted(blocks, key=lambda b: int(b.get("block_index", 0)))
    expected_prev = "0" * 64  # Genesis Hash

    for i, block in enumerate(sorted_blocks):
        current_index = int(block.get("block_index", 0))
        current_prev_hash = block.get("prev_hash")
        current_hash = block.get("block_hash")

        # 1. Index sequence continuity
        if current_index != i:
            errors.append(f"Index sequence mismatch at position {i}: expected {i}, found {current_index}")
            return False, errors

        # 2. Cryptographic chain continuity (prev_hash must match previous block's hash)
        if current_prev_hash != expected_prev:
            errors.append(
                f"Chain break at block index {current_index}: "
                f"expected prev_hash {expected_prev}, got {current_prev_hash}"
            )
            return False, errors

        # 3. Cryptographic payload integrity re-calculation
        raw_payload = f"{current_index}|{block.get('timestamp')}|{block.get('target')}|{block.get('checks_executed')}|{block.get('daemon_id')}|{current_prev_hash}"
        recomputed = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        if recomputed != current_hash:
            errors.append(
                f"Cryptographic payload tampering at block index {current_index}: "
                f"recorded {current_hash}, computed {recomputed}"
            )
            return False, errors

        expected_prev = current_hash

    return True, []

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point for S3 Bucket Event Notifications.
    Verifies SHA-256 Merkle chain integrity on uploaded audit evidence logs.
    """
    s3_client = boto3.client("s3") if boto3 else None
    sns_client = boto3.client("sns") if boto3 else None
    dynamo_client = boto3.client("dynamodb") if boto3 else None

    alarm_topic_arn = os.environ.get("COMPLIANCE_ALERT_SNS_ARN")
    ledger_table = os.environ.get("SENTINEL_DYNAMODB_TABLE", "sentinel_audit_ledger")

    records = event.get("Records", [])
    verified_count = 0
    errors = []

    for record in records:
        s3_info = record.get("s3", {})
        bucket_name = s3_info.get("bucket", {}).get("name")
        raw_key = s3_info.get("object", {}).get("key", "")
        object_key = urllib.parse.unquote_plus(raw_key)

        if not bucket_name or not object_key:
            continue

        try:
            # 1. Fetch uploaded log object from S3
            resp = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            content_bytes = resp["Body"].read()

            # 2. Compute SHA-256 checksum of payload
            computed_hash = hashlib.sha256(content_bytes).hexdigest()

            # 3. Parse JSONL blocks and verify chained integrity
            parsed_blocks = []
            lines = content_bytes.decode("utf-8").strip().split("\n")
            for line in lines:
                if line.strip():
                    parsed_blocks.append(json.loads(line))

            is_valid, chain_errors = verify_chain_continuity(parsed_blocks)
            if not is_valid:
                errors.extend(chain_errors)
                tamper_summary = "\n".join(chain_errors)

                # Trigger High-Priority Compliance Alarm via SNS
                if sns_client and alarm_topic_arn:
                    sns_client.publish(
                        TopicArn=alarm_topic_arn,
                        Subject="🚨 CRITICAL: AICPA Audit Evidence Chain Tamper Alert",
                        Message=f"SentinelAI Automated Verifier detected Merkle chain invalidation:\n\nBucket: {bucket_name}\nObject: {object_key}\nDetails:\n{tamper_summary}"
                    )
            else:
                # 4. Tag S3 Object with Verified Compliance Seal
                if s3_client:
                    s3_client.put_object_tagging(
                        Bucket=bucket_name,
                        Key=object_key,
                        Tagging={
                            "TagSet": [
                                {"Key": "ComplianceStatus", "Value": "VERIFIED_AT_C_205"},
                                {"Key": "IntegrityHash", "Value": computed_hash[:16]},
                                {"Key": "AuditorReady", "Value": "TRUE"},
                                {"Key": "ChainBlocksVerified", "Value": str(len(parsed_blocks))}
                            ]
                        }
                    )
                verified_count += 1

        except Exception as e:
            errors.append(f"Failed to process {object_key}: {str(e)}")

    return {
        "statusCode": 200 if not errors else 500,
        "body": json.dumps({
            "verified_objects": verified_count,
            "errors": errors,
            "status": "PASS" if not errors else "FAIL"
        })
    }
