#!/bin/bash
# userdata.sh — Auto-runs on EC2 launch to install Cowrie honeypot
# This script is injected into the EC2 instance via Terraform user_data

set -e
LOG="/var/log/honeypot-setup.log"
exec > >(tee -a $LOG) 2>&1

echo "========================================="
echo " Cloud Honeypot Lab — Bootstrap Starting"
echo " $(date)"
echo "========================================="

# ── Update system ──
apt-get update -y
apt-get upgrade -y

# ── Install dependencies ──
apt-get install -y \
  python3 python3-pip python3-venv \
  git docker.io docker-compose \
  curl wget unzip jq \
  libssl-dev libffi-dev build-essential

# ── Start Docker ──
systemctl enable docker
systemctl start docker

# ── Install Cowrie via Docker ──
echo "[*] Installing Cowrie honeypot..."
docker pull cowrie/cowrie:latest

mkdir -p /opt/cowrie/{log,dl,tty}

docker run -d \
  --name cowrie-honeypot \
  --restart always \
  -p 22:2222 \
  -p 23:2223 \
  -v /opt/cowrie/log:/cowrie/var/log/cowrie \
  -v /opt/cowrie/dl:/cowrie/var/lib/cowrie/downloads \
  -v /opt/cowrie/tty:/cowrie/var/lib/cowrie/tty \
  cowrie/cowrie:latest

echo "[+] Cowrie started on port 22"

# ── Install analysis pipeline ──
echo "[*] Installing analysis pipeline..."
git clone https://github.com/YOUR-USERNAME/Cloud-Honeypot-Detection-Lab.git /opt/honeypot-lab
cd /opt/honeypot-lab
pip3 install -r requirements.txt

# ── Setup cron — run pipeline every hour ──
echo "[*] Setting up automated pipeline..."
cat > /etc/cron.hourly/honeypot-pipeline << 'EOF'
#!/bin/bash
cd /opt/honeypot-lab
docker cp cowrie-honeypot:/cowrie/var/log/cowrie/cowrie.json logs/cowrie_logs.json 2>/dev/null
python3 pipeline.py --no-ai >> /var/log/honeypot-pipeline.log 2>&1
EOF
chmod +x /etc/cron.hourly/honeypot-pipeline

# ── Install CloudWatch agent ──
echo "[*] Installing CloudWatch agent..."
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/cowrie/log/cowrie.json",
            "log_group_name": "/honeypot/cowrie",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
  -s

echo "========================================="
echo " Bootstrap Complete — $(date)"
echo " Cowrie: $(docker ps | grep cowrie)"
echo "========================================="
