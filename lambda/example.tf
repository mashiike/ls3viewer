
resource "aws_iam_role" "ls3viewer" {
  name = "ls3viewer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "ls3viewer" {
  name   = "ls3viewer"
  path   = "/"
  policy = data.aws_iam_policy_document.ls3viewer.json
}

resource "aws_iam_role_policy_attachment" "ls3viewer" {
  role       = aws_iam_role.ls3viewer.name
  policy_arn = aws_iam_policy.ls3viewer.arn
}

data "aws_iam_policy_document" "ls3viewer" {
  statement {
    actions = [
      "ssm:GetParameter*",
      "ssm:DescribeParameters",
      "ssm:List*",
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "s3:GetObject",
      "s3:List*",
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "logs:GetLog*",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["*"]
  }
}

data "archive_file" "ls3viewer_dummy" {
  type        = "zip"
  output_path = "${path.module}/ls3viewer_dummy.zip"
  source {
    content  = "ls3viewer_dummy"
    filename = "bootstrap"
  }
  depends_on = [
    null_resource.ls3viewer_dummy
  ]
}

resource "null_resource" "ls3viewer_dummy" {}

resource "aws_lambda_function" "ls3viewer" {
  lifecycle {
    ignore_changes = all
  }

  function_name = "ls3viewer"
  role          = aws_iam_role.ls3viewer.arn

  handler  = "bootstrap"
  runtime  = "provided.al2"
  filename = data.archive_file.ls3viewer_dummy.output_path
}

resource "aws_lambda_alias" "ls3viewer" {
  lifecycle {
    ignore_changes = all
  }
  name             = "current"
  function_name    = aws_lambda_function.ls3viewer.arn
  function_version = aws_lambda_function.ls3viewer.version
}


resource "aws_lambda_function_url" "ls3viewer" {
  function_name      = aws_lambda_alias.ls3viewer.function_name
  qualifier          = aws_lambda_alias.ls3viewer.name
  authorization_type = "NONE"

  cors {
    allow_credentials = true
    allow_origins     = ["*"]
    allow_methods     = ["GET"]
    expose_headers    = ["keep-alive", "date"]
    max_age           = 0
  }
}

resource "aws_ssm_parameter" "GOOGLE_CLIENT_SECRET" {
  name        = "/ls3viewer/GOOGLE_CLIENT_SECRET"
  description = "GOOGLE_CLIENT_SECRET for ls3viewer"
  type        = "SecureString"
  value       = local.google_client_secret
}

resource "aws_ssm_parameter" "GOOGLE_CLIENT_ID" {
  name        = "/ls3viewer/GOOGLE_CLIENT_ID"
  description = "GOOGLE_CLIENT_ID for ls3viewer"
  type        = "SecureString"
  value       = local.google_client_id
}

output "lambda_function_url" {
  description = "Generated function URL"
  value       = aws_lambda_function_url.ls3viewer.function_url
}
