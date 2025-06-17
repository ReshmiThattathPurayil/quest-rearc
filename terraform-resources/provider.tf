#TERRAFORM VERSION, AWS PROVIDER, REGION AND ROLE TO BE USED TO ACCESS TERRAFORM IS DECLARED HERE. 
terraform {
  required_version = "~> 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.79.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
  }
