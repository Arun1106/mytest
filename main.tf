terraform {
  required_providers {
    aws = {
      source = "hashicorp/"
      version = "5.45.0"
    }
  }
}

provider "aws" {

}
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main1"
  }
}


##hi