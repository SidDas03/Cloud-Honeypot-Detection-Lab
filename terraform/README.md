# Terraform — Cloud Honeypot Infrastructure

This folder contains Infrastructure as Code (IaC) for deploying the honeypot lab on AWS using Terraform.

> **No AWS account needed to include this in your portfolio.** The files demonstrate IaC knowledge without requiring real cloud access.

---

## What Gets Deployed

```
AWS Cloud
├── VPC (isolated network)
│   └── Public Subnet
│       └── EC2 t2.micro (Honeypot Server)
│           ├── Cowrie SSH Honeypot (port 22)
│           ├── CloudWatch Agent (log forwarding)
│           └── Analysis Pipeline (runs hourly via cron)
├── GuardDuty (threat detection)
├── CloudTrail (API logging → S3)
├── SNS Topic (email alerts)
└── Elastic IP (fixed public IP)
```

---

## Files

| File | Purpose |
|------|---------|
| `main.tf` | Core infrastructure — VPC, EC2, GuardDuty, CloudTrail, SNS |
| `variables.tf` | Configurable settings — region, instance type, email |
| `outputs.tf` | Values shown after deploy — public IP, SSH command |
| `userdata.sh` | EC2 bootstrap script — auto-installs Cowrie on launch |

---

## How to Deploy (When You Have AWS Access)

### Prerequisites
```bash
# Install Terraform
# Windows: https://developer.hashicorp.com/terraform/downloads
# Linux/Mac:
brew install terraform       # Mac
sudo apt install terraform   # Ubuntu

# Configure AWS credentials
aws configure
# Enter: Access Key, Secret Key, Region (us-east-1)
```

### Deploy
```bash
cd terraform/

# Step 1 — Download AWS provider
terraform init

# Step 2 — Preview what will be created
terraform plan

# Step 3 — Actually deploy
terraform apply

# Type 'yes' when prompted
```

### After Deploy
Terraform will output:
```
honeypot_public_ip    = "54.87.123.201"
honeypot_instance_id  = "i-0a1b2c3d4e5f67890"
ssh_command           = "ssh -i your-key.pem ubuntu@54.87.123.201"
guardduty_detector_id = "abc123def456"
cloudtrail_bucket     = "cloud-honeypot-lab-cloudtrail-123456789012"
```

### Destroy (to avoid AWS charges)
```bash
terraform destroy
```

---

## Customization

Edit `variables.tf` to change settings:

```hcl
# Change region
variable "aws_region" {
  default = "ap-south-1"   # Mumbai
}

# Add alert email
variable "alert_email" {
  default = "your@email.com"
}
```

---

## Why Terraform for This Project

| Without Terraform | With Terraform |
|-------------------|----------------|
| Manually click through AWS console | One command deploys everything |
| Easy to misconfigure | Consistent, repeatable deployments |
| Hard to share setup | Anyone can deploy with `terraform apply` |
| No record of what was created | Full audit trail in `.tf` files |

This is exactly what **system integrators** do — automate infrastructure so it's reliable and reproducible.
