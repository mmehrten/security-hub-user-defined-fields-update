variable "account-id" {
  type        = string
  description = "The account to create resources in."
}
variable "app-shorthand-name" {
  type        = string
  description = "The shorthand name of the app being provisioned."
  default     = "demo"
}
variable "region" {
  type    = string
  default = "us-gov-west-1"
}
variable "partition" {
  type    = string
  default = "aws-us-gov"
}
variable "name" {
  type    = string
  default = "update-secuity-hub"
}

provider "aws" {
  region = var.region
}

resource "aws_iam_role_policy" "main" {
  name = "${var.app-shorthand-name}.iam.role.lambda.${var.name}"
  role = aws_iam_role.main.id
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : "logs:CreateLogGroup",
          "Resource" : "arn:${var.partition}:logs:${var.region}:${var.account-id}:*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "securityhub:GetFindings",
            "securityhub:BatchUpdateFindings",
            "inspector2:BatchGetFindingDetails"
          ],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource" : [
            "arn:${var.partition}:logs:${var.region}:${var.account-id}:log-group:/aws/lambda/${var.name}:*"
          ]
        }
      ]
  })
}


resource "aws_iam_role" "main" {
  name                = "${var.app-shorthand-name}.iam.role.lambda.${var.name}"
  managed_policy_arns = []
  assume_role_policy  = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Action": "sts:AssumeRole",
     "Principal": {"Service": "lambda.amazonaws.com"},
     "Effect": "Allow"
   }
 ]
}
EOF
}

data "archive_file" "main" {
  type        = "zip"
  source_file = "./update_finding.py"
  output_path = "lambda.zip"
}

resource "aws_lambda_function" "main" {
  filename         = "lambda.zip"
  function_name    = var.name
  role             = aws_iam_role.main.arn
  handler          = "update_finding.lambda_handler"
  source_code_hash = data.archive_file.main.output_base64sha256
  runtime          = "python3.10"
  layers           = ["arn:${var.partition}:lambda:${var.region}:${var.account-id}:layer:boto3:1"]
  timeout          = 60
}

resource "aws_cloudwatch_event_rule" "main" {
  name = "secuityhub-inspector-findings"
  event_pattern = jsonencode({
    "source" : ["aws.securityhub"],
    "detail-type" : ["Security Hub Findings - Imported"],
    "detail" : {
      "findings" : {
        "ProductArn" : ["arn:${var.partition}:securityhub:${var.region}::product/aws/inspector"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "main" {
  rule      = aws_cloudwatch_event_rule.main.name
  target_id = aws_cloudwatch_event_rule.main.name
  arn       = aws_lambda_function.main.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.main.arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.main.arn
}
