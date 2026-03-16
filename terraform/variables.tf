# variables.tf — Configurable settings for the honeypot deployment

variable "aws_region" {
  description = "AWS region to deploy the honeypot"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for naming all resources"
  type        = string
  default     = "cloud-honeypot-lab"
}

variable "instance_type" {
  description = "EC2 instance type (t2.micro is free tier eligible)"
  type        = string
  default     = "t2.micro"
}

variable "vpc_cidr" {
  description = "CIDR block for the honeypot VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the honeypot subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "key_pair_name" {
  description = "Name of existing AWS key pair for SSH access"
  type        = string
  default     = ""
}

variable "alert_email" {
  description = "Email address for GuardDuty/SNS alerts (leave blank to skip)"
  type        = string
  default     = ""
}
