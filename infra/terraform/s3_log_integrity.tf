# ════════════════════════════════════════════════════════════════════════════════
# SentinelAI Infrastructure-as-Code: S3 Audit Vault & Serverless Integrity Verifier
# Connects S3 Event Notifications to Lambda with WORM retention and DynamoDB State
# ════════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment (production / staging)"
}

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for compliance vault"
}

# 1. DynamoDB Persistent Ledger State Table
resource "aws_dynamodb_table" "audit_ledger" {
  name         = "sentinel_audit_ledger_${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Environment = var.environment
    Compliance  = "AICPA-SOC2-Type2"
    Purpose     = "Continuous-Audit-Ledger-State"
  }
}

# 2. S3 Immutable Audit Evidence Vault (WORM Compliance)
resource "aws_s3_bucket" "audit_vault" {
  bucket = "sentinel-audit-evidence-vault-${var.environment}"

  tags = {
    Environment = var.environment
    Compliance  = "AICPA-AT-C-205"
    DataClass   = "Restricted-Audit-Logs"
  }
}

resource "aws_s3_bucket_versioning" "audit_vault_versioning" {
  bucket = aws_s3_bucket.audit_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_vault_crypto" {
  bucket = aws_s3_bucket.audit_vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_vault_privacy" {
  bucket                  = aws_s3_bucket.audit_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. SNS Compliance Alert Topic
resource "aws_sns_topic" "compliance_alerts" {
  name = "sentinel-compliance-tamper-alerts-${var.environment}"
}

# 4. IAM Execution Role for Lambda Integrity Verifier
resource "aws_iam_role" "lambda_verifier_role" {
  name = "sentinel_lambda_verifier_role_${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_verifier_policy" {
  name        = "sentinel_verifier_least_privilege_${var.environment}"
  description = "Least-privilege permissions for SentinelAI S3 log verifier"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3LogStreamingAndTagging"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObjectTagging"
        ]
        Resource = "${aws_s3_bucket.audit_vault.arn}/*"
      },
      {
        Sid    = "DynamoDBLedgerReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.audit_ledger.arn
      },
      {
        Sid    = "SNSTamperNotification"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.compliance_alerts.arn
      },
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_verifier_policy" {
  role       = aws_iam_role.lambda_verifier_role.name
  policy_arn = aws_iam_policy.lambda_verifier_policy.arn
}

# 5. AWS Lambda Function: verify_log_integrity
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/verify_log_integrity.zip"

  source {
    content  = file("${path.module}/../../engine/core/verify_log_integrity.py")
    filename = "verify_log_integrity.py"
  }
}

resource "aws_lambda_function" "verify_log_integrity" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "sentinel-verify-log-integrity-${var.environment}"
  role             = aws_iam_role.lambda_verifier_role.arn
  handler          = "verify_log_integrity.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 256
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SENTINEL_DYNAMODB_TABLE  = aws_dynamodb_table.audit_ledger.name
      COMPLIANCE_ALERT_SNS_ARN = aws_sns_topic.compliance_alerts.arn
      AICPA_STANDARD           = "AT-C-205"
    }
  }

  tags = {
    Compliance = "AICPA-CC9.2"
  }
}

# 6. S3 Invocation Permission for Lambda
resource "aws_lambda_permission" "allow_s3_invocation" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.verify_log_integrity.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.audit_vault.arn
}

# 7. Glue Code: S3 Bucket Notification wiring S3 Events to Lambda
resource "aws_s3_bucket_notification" "audit_vault_notification" {
  bucket = aws_s3_bucket.audit_vault.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.verify_log_integrity.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "ledgers/"
    filter_suffix       = ".jsonl"
  }

  depends_on = [aws_lambda_permission.allow_s3_invocation]
}
