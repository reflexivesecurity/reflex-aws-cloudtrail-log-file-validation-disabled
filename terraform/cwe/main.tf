module "cwe" {
  source      = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe?ref=v0.6.0"
  name        = "CloudTrailLogFileValidationDisabled"
  description = "Rule to detect when file validation is disabled for a CloudTrail trail."

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

}