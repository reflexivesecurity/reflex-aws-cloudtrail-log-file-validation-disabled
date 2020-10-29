module "cwe" {
  source      = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/cwe?ref=v2.1.3"
  name        = "CloudtrailLogFileValidationDisabled"
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
