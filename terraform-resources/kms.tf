
resource "aws_kms_key" "quest_poc_key" {
  description             = "kms key for quest poc"
  enable_key_rotation     = "true"

  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "kms-all-access-policy",
    Statement = [
      {
        Sid       = "AllowRootAccountAccess",
        Effect    = "Allow",
        Principal = {
          AWS = "arn:aws:iam::745805182316:root"
        },
        Action    = "kms:*",
        Resource  = "*"
      },
      {
        Sid       = "AllowAllServicesToUseTheKey",
        Effect    = "Allow",
        Principal = "*",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "this" {
  name          = "alias/quest-poc-key"
  target_key_id = aws_kms_key.quest_poc_key.key_id
}

data "aws_caller_identity" "current" {}

# outputs.tf
output "key_id" {
  value = aws_kms_key.quest_poc_key.key_id
}

output "key_arn" {
  value = aws_kms_key.quest_poc_key.arn
}
