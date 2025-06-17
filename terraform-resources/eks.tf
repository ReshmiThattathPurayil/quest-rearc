
################################################################################
#LOCALS FOR QUEST EKS CLUSTER
################################################################################
locals {
  ami_id_poc_eks_bastion_app          = "ami-049377d9217848781"
  ami_id_poc_eks_ng                   = "ami-049377d9217848781"
  app_subnet_ids_poc_eks_bastion_app  = module.vpc.private_subnets
  app_subnet_az_poc_bastion_app           = ["${local.region}a", "${local.region}b", "${local.region}c"]
}



################################################################################
#EC2 BASTION FOR QUEST EKS CLUSTER
################################################################################
module "quest_poc_eks_bastion_ec2_01" {
  source                  = "./modules-prod/ec2"
  name                    = "${local.aws_account_name}-poc-eks-bastion-ec2-01"
  ami                     = local.ami_id_poc_eks_bastion_app
  instance_type           = "t3a.medium"
user_data = base64encode(<<-EOF
  #!/bin/bash
  /etc/eks/bootstrap.sh ${module.quest_poc_eks_cluster_01.cluster_name} \
    --b64-cluster-ca '${module.quest_poc_eks_cluster_01.cluster_certificate_authority_data}' \
    --apiserver-endpoint '${module.quest_poc_eks_cluster_01.cluster_endpoint}'
EOF
)
  subnet_id = local.app_subnet_ids_poc_eks_bastion_app[0]

  vpc_security_group_ids  = [module.quest_poc_eks_cluster_sg_01.security_group_id]
  iam_instance_profile    = aws_iam_instance_profile.poc_ec2_eks_access_instance_profile_01.name
  key_name                = "my-key"
  root_volume_size        = 50
  enable_volume_tags      = true
  disable_api_termination = true
  ebs_optimized           = true
  tags = merge(
    local.tags,
    { "application" = "poc-eks-bastion-app" },
    { "tier" = "app" },
    { "poc" = "${local.aws_account_name}-poc-eks-bastion-app" },
    { "customer" = "quest-mt" }
  )
  volume_tags = merge(
    local.tags,
    { "application" = "poc-eks-bastion-app" },
    { "tier" = "app" },
    { "poc" = "${local.aws_account_name}-poc-eks-bastion-app" },
    { "customer" = "quest-mt" }
  )
}

resource "aws_iam_instance_profile" "poc_ec2_eks_access_instance_profile_01" {
  name = "${local.aws_account_name}-poc-ec2-eks-access-role-01"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.name
  tags = merge(local.tags,
  {"application"="session-manager"}
  )
}

resource "aws_iam_role" "poc_ec2_eks_access_instance_role" {
  name                = "${local.aws_account_name}-poc-ec2-eks-access-role-01"
  path               = "/system/"
  assume_role_policy  = data.aws_iam_policy_document.quest_asg_sns_instance_assume_role_policy.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy","arn:aws:iam::aws:policy/AdministratorAccess"]
  tags = merge(local.tags,
  {"application"="session-manager"}
  )
}

data "aws_iam_policy_document" "quest_asg_sns_instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}


resource "aws_iam_role_policy" "assume_role_policy_for_poc_eks_poc_cross_account-01" {
  name = "${local.aws_account_name}-poc-assume-role-cross-account-policy-01"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "quest_poc_ec2_eks_policy" {
  name = "${local.aws_account_name}-poc-ec2-eks-policy-01"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor3",
            "Effect": "Allow",
            "Action": "eks:DescribeCluster",
            "Resource": "${module.quest_poc_eks_cluster_01.cluster_arn}"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "quest_common_s3_access_policy_01" {
  name = "${local.aws_account_name}-comman-s3-bucket-policy"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
               "s3:GetObject",
               "s3:PutObject"
            ],
            "Resource": [
              "*"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt",
                "kms:Encrypt"
            ],
            "Resource": "*" 
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "quest_poc_ec2_ecr_readonly_policy" {
  name = "${local.aws_account_name}-poc-ec2-ecr-readonly-policy-01"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "quest_poc_ec2_ecr_write_policy" {
  name = "${local.aws_account_name}-poc-ec2-ecr-write-policy-01"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.id
policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:PutImage"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

## CREATING POLICY FOR RETRIEVING SECRETS VALUE
resource "aws_iam_role_policy" "assume_role_policy_for_poc_eks_prisma_secrets_policy" {
  name = "${local.aws_account_name}-poc-eks-prisma-secret-policy-01"
  role = aws_iam_role.poc_ec2_eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
          "Sid": "VisualEditor0",
          "Effect": "Allow",
          "Action": [
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret"
          ],
          "Resource": [ "*"
          ]
        },
        {
          "Sid": "VisualEditor1",
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ],
          "Resource": "*"
        }
    ]
}
EOF

}


################################################################################
# QUEST EKS VPC CNI IAM ROLE FOR SERVICE ACCOUNT
################################################################################
module "quest_poc_eks_vpc_cni_irsa_01" {
  source  = "./modules-prod/iam/sub-module/role-eks"
  role_name             = "${local.aws_account_name}-poc-eks-vpc-cni-irsa-01"
  attach_vpc_cni_policy = true
  vpc_cni_enable_ipv4   = true
  oidc_providers = {
    main = {
      provider_arn               = module.quest_poc_eks_cluster_01.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }
  tags = local.tags
}
################################################################################
# QUEST EKS EBS CSI DRIVER IAM ROLE FOR SERVICE ACCOUNT
################################################################################
resource "aws_iam_policy" "quest_poc_eks_ebs_csi_driver_kms_policy_01" {
  name        = "${local.aws_account_name}-poc-eks-ebs-csi-driver-kms-policy-01"
  description = "This Policy is for ebs csi driver irsa kms permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant" ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
  tags = local.tags
}
module "quest_poc_eks_ebs_csi_driver_irsa_01" {
  source  = "./modules-prod/iam/sub-module/role-eks"
  role_name = "${local.aws_account_name}-poc-eks-ebs-csi-driver-irsa-01"
  attach_ebs_csi_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.quest_poc_eks_cluster_01.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
  
  role_policy_arns = {
    additional           = aws_iam_policy.quest_poc_eks_ebs_csi_driver_kms_policy_01.arn
  }
  tags = local.tags
}

# ################################################################################
# # QUEST EKS EFS CSI DRIVER
# ################################################################################
resource "aws_iam_policy" "quest_poc_eks_efs_csi_driver_kms_policy_01" {
  name        = "${local.aws_account_name}-poc-eks-efs-csi-driver-kms-policy-01"
  description = "This Policy is for efs csi driver irsa kms permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant" ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
  tags = local.tags
}

module "quest_poc_eks_efs_csi_driver_irsa_01" {
  source  = "./modules-prod/iam/sub-module/role-eks"
  role_name = "${local.aws_account_name}-poc-eks-efs-csi-driver-irsa-01"
  attach_efs_csi_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.quest_poc_eks_cluster_01.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]

    role_policy_arns = {
    additional           = "arn:aws:iam::aws:policy/AdministratorAccess"
    additional_efs_policy= "arn:aws:iam::aws:policy/AdministratorAccess"
  }
    }
  }
  

  tags = local.tags
}

################################################################################
# QUEST EKS LOADBALANCER CONTROLLER IAM ROLE FOR SERVICE ACCOUNT
################################################################################
resource "aws_iam_policy" "quest_poc_eks_load_balancer_controller_elb_policy_01" {
  name        = "${local.aws_account_name}-poc-eks-loadbalancer-controller-elb-policy-01"
  description = "This Policy is for loadbalancer controller irsa elb permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "elasticloadbalancing:AddTags" ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
  tags = local.tags
}

module "quest_poc_eks_load_balancer_controller_irsa_01" {
  source  = "./modules-prod/iam/sub-module/role-eks"
  role_name = "${local.aws_account_name}-poc-eks-load-balancer-controller-irsa-01"
  attach_load_balancer_controller_policy = true
  oidc_providers = {
    ex = {
      provider_arn               = "${module.quest_poc_eks_cluster_01.oidc_provider_arn}"
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  role_policy_arns = {
    additional           = aws_iam_policy.quest_poc_eks_load_balancer_controller_elb_policy_01.arn
  }

  tags = local.tags
}

################################################################################
# QUEST EKS CUSTER AUTOSCALER IAM ROLE FOR SERVICE ACCOUNT
################################################################################
resource "aws_iam_policy" "quest_poc_eks_cluster_autoscaler_policy_01" {
  name        = "${local.aws_account_name}-poc-eks-cluster-autoscaler-policy-01"
  description = "This Policy is for cluster autoscaler irsa permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "kms:Decrypt", "kms:GenerateData*", "kms:Encrypt" ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [ "autoscaling:SetDesiredCapacity" ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [ "autoscaling:TerminateInstanceInAutoScalingGroup" ]
        Effect   = "Allow"
        Resource = "arn:aws:autoscaling:ap-south-1:${local.aws_account_id}:autoScalingGroup:*:autoScalingGroupName/eks-quest-poc-eks-managed-ng-*"
      },
    ]
  })
  tags = local.tags
}

module "quest_poc_eks_cluster_autoscaler_irsa_01" {
  source  = "./modules-prod/iam/sub-module/role-eks"
  role_name = "${local.aws_account_name}-poc-eks-cluster-autoscaler-irsa-01"
  attach_cluster_autoscaler_policy = true
  oidc_providers = {
    ex = {
      provider_arn               = "${module.quest_poc_eks_cluster_01.oidc_provider_arn}"
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

  role_policy_arns = {
    additional           = aws_iam_policy.quest_poc_eks_cluster_autoscaler_policy_01.arn
  }

  tags = local.tags
}

################################################################################
# QUEST EKS CLUSTER SECURITY GROUP
################################################################################
module "quest_poc_eks_cluster_sg_01" {
  source = "./modules-prod/security-group"
  name   = "${local.aws_account_name}-poc-eks-cluster-sg-01"
  vpc_id = module.vpc.vpc_id	
  ingress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic to internal vpc range"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
  tags = merge(
    local.tags,
    { "application" = "eks-cluster" },
    { "tier" = "app" }
  )
}
################################################################################
# QUEST EKS MANAGED NODE GROUP SECURITY GROUP
################################################################################
module "quest_poc_eks_managed_node_sg_01" {
  source = "./modules-prod/security-group"
  name   = "${local.aws_account_name}-poc-eks-managed-node-sg-01"
  vpc_id = module.vpc.vpc_id	
  ingress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic to internal vpc range"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
  tags = merge(
    local.tags,
    { "application" = "eks-cluster" },
    { "tier" = "app" }
  )
}
################################################################################
# QUEST EKS MODULE
################################################################################
module "quest_poc_eks_cluster_01" {
  source  = "./modules-prod/eks"
  
  ## CLUSTER GENERAL INPUTS
  cluster_name                   = "${local.aws_account_name}-poc-eks-cluster-01"
  cluster_version                = "1.29"
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access = false
  ## CLUSTER ADDONS
  cluster_addons = {
    coredns = {
      most_recent              = false
      addon_version            = "v1.11.1-eksbuild.9"
    }
    kube-proxy = {
      most_recent              = false
      addon_version            = "v1.29.3-eksbuild.2"
    }
    vpc-cni = {
      most_recent              = false
      addon_version            = "v1.18.1-eksbuild.1"
      service_account_role_arn = module.quest_poc_eks_vpc_cni_irsa_01.iam_role_arn
      configuration_values = jsonencode({
        env = {
          # Reference docs https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
    aws-ebs-csi-driver ={
      most_recent              = false
      addon_version            = "v1.30.0-eksbuild.1"
      service_account_role_arn = module.quest_poc_eks_ebs_csi_driver_irsa_01.iam_role_arn
    }
  }
  
  ## CLUSTER NETWORKING
  vpc_id                   = module.vpc.vpc_id	
  subnet_ids               = local.app_subnet_ids_poc_eks_bastion_app
  control_plane_subnet_ids = local.app_subnet_ids_poc_eks_bastion_app
  ## CLUSTER SECURITY
  cluster_security_group_id = "${module.quest_poc_eks_managed_node_sg_01.security_group_id}"
  create_kms_key = false
  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.quest_poc_key.arn
  }
  
  ## CLUSTER IAM ROLE
  iam_role_use_name_prefix = false
  iam_role_name = "${local.aws_account_name}-poc-eks-cluster-role-01"
  
  ## CLUSTER SG
  cluster_security_group_name = "${local.aws_account_name}-poc-eks-cluster-default-sg-01"
  cluster_security_group_use_name_prefix = false
  cluster_security_group_additional_rules = {
    ingress_internal_range = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "allowing port 443 from internal range for api communication"
      type = "ingress"
      cidr_blocks = ["10.0.0.0/8"]
    }
  }
  
  ## CLUSTER NODE SG
  node_security_group_name = "${local.aws_account_name}-poc-eks-cluster-default-node-sg-01"
  node_security_group_use_name_prefix = false
  node_security_group_tags = {
    "kubernetes.io/cluster/${local.aws_account_name}-poc-eks-cluster-01" = null
  }
  
  ## CLUSTER AWS AUTH CONFIGMAP
  create_aws_auth_configmap = false
  manage_aws_auth_configmap = false
  tags = local.tags
}
#IAM POLICY FOR EKS NODE GROUP
resource "aws_iam_role" "quest_poc_eks_managed_role" {
  name = "${local.aws_account_name}-poc-eks-managed-role-01"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy", "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy", "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", "arn:aws:iam::aws:policy/AmazonElasticFileSystemReadOnlyAccess", "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy", "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
  inline_policy {
    name = "${local.aws_account_name}-eks-managed-ng-additional-policy-01"
    policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
			Effect = "Allow",
			Action = "kms:Decrypt",
			Resource = "*"
	  },
        {
          "Sid": "VisualEditor1",
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ],
          "Resource": [
            "*"
          ]
        },
        {
            "Sid": "VisualEditor2",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:ListBucket",
                "s3:GetObjectVersionAcl",
                "s3:GetObjectTagging",
                "s3:GetObjectAcl",
                "s3:GetObject"
            ],
            "Resource": [
              "*"
            ]
        }
    ]
  })
  }
}
locals{
    eks_userdata_poc = <<-EOT
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary="//"

      --//
      #!/bin/bash
      Content-Type: text/x-shellscript; charset="us-ascii"
      set -ex
      B64_CLUSTER_CA="${module.quest_poc_eks_cluster_01.cluster_certificate_authority_data}"
      API_SERVER_URL="${module.quest_poc_eks_cluster_01.cluster_endpoint}"
      /etc/eks/bootstrap.sh "${module.quest_poc_eks_cluster_01.cluster_name}" --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL 
      
      --//--
  EOT
}
#LAUNCH TEMPLATE FOR QUEST EKS NODE 01
module "quest_poc_eks_lt_01" {
  source = "./modules-prod/launch-template"
  # AUTOSCALING GROUP
  create = false
 
  # LAUNCH TEMPLATE
  name = "${local.aws_account_name}-poc-eks-lt-01"
  security_groups    = [module.quest_poc_eks_managed_node_sg_01.security_group_id, module.quest_poc_eks_cluster_01.cluster_primary_security_group_id]
  create_launch_template      = true
  update_default_version      = true
  launch_template_use_name_prefix = false 
  launch_template_name        = "${local.aws_account_name}-poc-eks-lt-01"
  image_id          = "ami-049377d9217848781"
  key_name          = "my-key"
  block_device_mappings = [
    {
      # Root volume
      device_name = "/dev/xvda"
      no_device   = 0
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 50
        volume_type           = "gp3"
      }
      }
  ]
  user_data         = base64encode(local.eks_userdata_poc)
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 32
    instance_metadata_tags      = "enabled"
  }
  tag_specifications = [
      {
        resource_type = "instance"
        tags = merge(
          {"application" = "poc-eks"},
          {"Name" = "${local.aws_account_name}-poc-eks-ng-01"},
          { "poc" = "${local.aws_account_name}-poc-eks"},
          { "customer" = "quest-mt" }
        )
      },
      {
        resource_type = "volume"
        tags = merge(
          local.tags,
          {"application" = "poc-eks"},
          {"Name" = "${local.aws_account_name}-poc-eks-ng-01"},
          { "poc" = "${local.aws_account_name}-poc-eks"},
          { "customer" = "quest-mt" }
        )
      },
    ]
  tags = merge(
    local.tags,
      {"application" = "poc-eks"},
      {"tier" = "target-group"},
      { "poc" = "${local.aws_account_name}-poc-eks"},
      { "customer" = "quest-mt" }
    )
}


#####################################################
#QUEST EKS MANAGED NODE GROUP 01 MODULE
#####################################################
module "quest_poc_eks_managed_node_group_01" {
  source  = "./modules-prod/eks/sub-module/eks-managed-node-group"
  # GENERAL
  name            = "${local.aws_account_name}-poc-eks-managed-ng-01"
  use_name_prefix = false
  cluster_name    = module.quest_poc_eks_cluster_01.cluster_name
     
  #NETWORKING
  subnet_ids = module.vpc.private_subnets
  
  # LAUNCH TEMPLATE
  create_launch_template = "false"
  use_custom_launch_template = "true"
  launch_template_id  =  module.quest_poc_eks_lt_01.launch_template_id
  launch_template_version = "$Latest"
  ami_type = "CUSTOM"
  
  # CAPACITY
  instance_types = ["t3a.medium", "t3a.medium"]
  min_size     = 1
  max_size     = 2
  desired_size = 1
  # IAM
  create_iam_role = false
  iam_role_arn = aws_iam_role.quest_poc_eks_managed_role.arn
  iam_role_use_name_prefix = false
  iam_role_attach_cni_policy = true
}