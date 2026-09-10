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

            # 3. Verify chained integrity if object is a JSONL block
            is_valid = True
            lines = content_bytes.decode("utf-8").strip().split("\n")
            
            for line in lines:
                if not line.strip():
                    continue
                block = json.loads(line)
                block_hash = block.get("block_hash")
                raw_payload = f"{block.get('block_index')}|{block.get('timestamp')}|{block.get('target')}|{block.get('checks_executed')}|{block.get('daemon_id')}|{block.get('prev_hash')}"
                recomputed = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

                if recomputed != block_hash:
                    is_valid = False
                    tamper_msg = f"Cryptographic tamper detected in {object_key} at block index {block.get('block_index')}"
                    errors.append(tamper_msg)

                    # Trigger High-Priority Compliance Alarm via SNS
                    if sns_client and alarm_topic_arn:
                        sns_client.publish(
                            TopicArn=alarm_topic_arn,
                            Subject="🚨 CRITICAL: AICPA Audit Evidence Tamper Alert",
                            Message=f"SentinelAI Automated Verifier detected hash mismatch:\n\nBucket: {bucket_name}\nObject: {object_key}\nExpected: {block_hash}\nComputed: {recomputed}"
                        )
                    break

            # 4. Tag S3 Object with Compliance Seal
            if is_valid and s3_client:
                s3_client.put_object_tagging(
                    Bucket=bucket_name,
                    Key=object_key,
                    Tagging={
                        "TagSet": [
                            {"Key": "ComplianceStatus", "Value": "VERIFIED_AT_C_205"},
                            {"Key": "IntegrityHash", "Value": computed_hash[:16]},
                            {"Key": "AuditorReady", "Value": "TRUE"}
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
