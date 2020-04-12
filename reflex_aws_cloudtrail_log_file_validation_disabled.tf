module "reflex_aws_cloudtrail_log_file_validation_disabled" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.5.8"
  rule_name        = "CloudTrailLogFileValidationDisabled"
  rule_description = "Rule to detect when file validation is disabled for a CloudTrail trail."

  event_pattern = <<PATTERN
{
  "source": [
    "aws.cloudtrail"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "CreateTrail",
      "UpdateTrail"
    ]
  }
}
PATTERN

  function_name   = "CloudTrailLogFileValidationDisabled"
  source_code_dir = "${path.module}/source"
  handler         = "reflex_aws_cloudtrail_log_file_validation_disabled.lambda_handler"
  lambda_runtime  = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn,
  }



  queue_name    = "CloudTrailLogFileValidationDisabled"
  delay_seconds = 0

  target_id = "CloudTrailLogFileValidationDisabled"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
