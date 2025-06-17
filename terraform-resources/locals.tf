#DEFINING THE COMMON TAGS AT SINGLE PLACE
locals {
  region = "ap-south-1"
  aws_account_id = "745805182316"
  aws_account_name = "quest"
  tags = {
	application = "na"
	tier = "na"
	region = "mumbai"
	owner = "reshmi"
	created = "terraform" 
  }
}