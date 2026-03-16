# main.tf — Cloud Honeypot Detection Lab
# Deploys a simulated honeypot EC2 instance on AWS
#
# NOTE: This is for reference/portfolio purposes.
# You do NOT need a real AWS account to include this in your project.
# It demonstrates Infrastructure as Code (IaC) knowledge.
#
# To actually deploy (when you have AWS access):
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}


# Get latest Ubuntu 22.04 AMI automatically
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (Ubuntu)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

resource "aws_vpc" "honeypot_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Project     = var.project_name
    Environment = "honeypot"
  }
}

# Internet Gateway — allows inbound internet traffic
resource "aws_internet_gateway" "honeypot_igw" {
  vpc_id = aws_vpc.honeypot_vpc.id

  tags = {
    Name    = "${var.project_name}-igw"
    Project = var.project_name
  }
}

# Public Subnet
resource "aws_subnet" "honeypot_subnet" {
  vpc_id                  = aws_vpc.honeypot_vpc.id
  cidr_block              = var.subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_name}-subnet"
    Project = var.project_name
  }
}

# Route Table 
resource "aws_route_table" "honeypot_rt" {
  vpc_id = aws_vpc.honeypot_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot_igw.id
  }

  tags = {
    Name    = "${var.project_name}-rt"
    Project = var.project_name
  }
}

resource "aws_route_table_association" "honeypot_rta" {
  subnet_id      = aws_subnet.honeypot_subnet.id
  route_table_id = aws_route_table.honeypot_rt.id
}

resource "aws_security_group" "honeypot_sg" {
  name        = "${var.project_name}-sg"
  description = "Honeypot security group - allows SSH and HTTP for attacker luring"
  vpc_id      = aws_vpc.honeypot_vpc.id

  # Allow SSH from anywhere (honeypot needs this to attract attackers)
  ingress {
    description = "SSH honeypot"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTP
  ingress {
    description = "HTTP honeypot"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow Cowrie honeypot port
  ingress {
    description = "Cowrie SSH honeypot"
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-sg"
    Project = var.project_name
  }
}

resource "aws_iam_role" "honeypot_role" {
  name = "${var.project_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Project = var.project_name
  }
}

# Attach CloudWatch policy — for sending logs to CloudWatch
resource "aws_iam_role_policy_attachment" "cloudwatch_policy" {
  role       = aws_iam_role.honeypot_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance profile — links IAM role to EC2
resource "aws_iam_instance_profile" "honeypot_profile" {
  name = "${var.project_name}-profile"
  role = aws_iam_role.honeypot_role.name
}

resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.honeypot_subnet.id
  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.honeypot_profile.name
  key_name               = var.key_pair_name

  # IMDSv2 enforced — prevents metadata theft attacks
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Forces IMDSv2
    http_put_response_hop_limit = 1
  }

  # Root volume
  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # User data script — auto-installs Cowrie on launch
  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    project_name = var.project_name
  }))

  tags = {
    Name        = "${var.project_name}-instance"
    Project     = var.project_name
    Environment = "honeypot"
    ManagedBy   = "terraform"
  }
}

# Elastic IP — gives the honeypot a fixed public IP
resource "aws_eip" "honeypot_eip" {
  instance = aws_instance.honeypot.id
  domain   = "vpc"

  tags = {
    Name    = "${var.project_name}-eip"
    Project = var.project_name
  }
}

resource "aws_guardduty_detector" "honeypot_detector" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Project = var.project_name
  }
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Project = var.project_name
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "honeypot_trail" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]

  tags = {
    Project = var.project_name
  }
}

resource "aws_sns_topic" "honeypot_alerts" {
  name = "${var.project_name}-alerts"

  tags = {
    Project = var.project_name
  }
}

resource "aws_sns_topic_subscription" "email_alert" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.honeypot_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
