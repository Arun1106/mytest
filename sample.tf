data "aws_iam_policy_document" "invocation_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "invocation_role" {
  name               = "api_gateway_auth_invocation"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.invocation_assume_role.json
}

data "aws_iam_policy_document" "invocation_policy" {
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "invocation_policy" {
  name   = "default"
  role   = aws_iam_role.invocation_role.id
  policy = data.aws_iam_policy_document.invocation_policy.json
}


data "aws_lambda_function" "existing" {
  function_name = "auth"
}

output "arn" {
  value = data.aws_lambda_function.existing.invoke_arn
}
data "aws_region" "current" {}
locals {
  processed_placeholders = {
    for api in var.apilist : api.api_name => {
      for key, value in api.placeholder : key => (
        startswith(key, "lambda") ? 
        "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/arn:aws:lambda:${data.aws_region.current.name}:818363358821:function:${value}/invocations"
        : value
      )
    }
  }
    lambda_placeholders = {
    for api in var.apilist : api.api_name => distinct([
      for key, value in api.placeholder : value
      if startswith(key, "lambda") && value != null
    ])
    if length([for k, v in api.placeholder : v if startswith(k, "lambda") && v != null]) > 0
  }
  all_permissions = flatten([
    for api_name, lambda_list in local.lambda_placeholders : [
      for function in lambda_list : {
        api_name      = api_name
        function_name = function
      }
    ]
  ])
}

output "lambda_placeholders" {
  value = local.lambda_placeholders
}

module "api" {
  source = "./modules"
  for_each = {for api in var.apilist : api.api_name => api}
  body = templatefile("${path.module}/sample.tpl", {placeholder = local.processed_placeholders[each.key]})
  api_name = each.value.api_name
  authorizer_credentials = aws_iam_role.invocation_role.arn
  authorizer_uri =  try("arn:aws:apigateway:${each.value.region}:lambda:path/2015-03-31/functions/${data.aws_lambda_function.existing.arn}/invocations", null)
}

variable "apilist" {
  
}



resource "aws_lambda_permission" "allow_api_invoke" {
  for_each = {
    for perm in local.all_permissions :
    "${perm.api_name}-${perm.function_name}" => perm
  }

  # Unique statement ID for each permission
  statement_id  = "${each.value.api_name}-${each.value.function_name}-AllowAPIInvoke"

  action        = "lambda:InvokeFunction"
  function_name = each.value.function_name

  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:ap-south-1:818363358821:*"  # Replace with your actual ARN
}













