data "aws_caller_identity" "current" {}
module "assume_role" {
  source               = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/sqs_lambda/modules/iam_assume_role?ref=v2.1.3"
  custom_lambda_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudtrail:UpdateTrail"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF


  function_name             = "CloudtrailLogFileValidationDisabled"
  lambda_execution_role_arn = "arn:aws:iam::${var.parent_account}:role/ReflexCloudtrailLogFileValidationDisabledLambdaExecution"

}
