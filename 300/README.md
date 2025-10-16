# 300 - Learning Our Subject

# Learning Google Cloud Platform

A hands-on project demonstrating GCP services through a **Cloud Security Monitoring & Alerting System** built by a Cyber Security Engineer.

## 🎯 Project Overview

This repository contains a production-ready security monitoring system that leverages multiple GCP services to detect misconfigurations, analyze audit logs, and alert on suspicious activities in real-time.

## 🔧 Technologies & Services Used

### Core GCP Services

- **Cloud Functions**: Serverless compute for security checks
- **Cloud Storage**: Storing security reports and logs
- **Pub/Sub**: Event-driven messaging for alerts
- **Cloud Logging**: Centralized log management
- **Cloud Scheduler**: Automated security scans
- **Secret Manager**: Secure credential storage
- **IAM**: Identity and Access Management
- **BigQuery**: Log analysis and querying

### Additional Tools

- **Python 3.11**: Primary programming language
- **Terraform**: Infrastructure as Code
- **Docker**: Containerization
- **Google Cloud SDK**: CLI tools

## 🏗️ Architecture

```
Cloud Scheduler → Cloud Function (Security Scanner)
                        ↓
                  [Checks Resources]
                        ↓
                  Cloud Storage ← Security Reports
                        ↓
                    Pub/Sub → Cloud Function (Alert Handler)
                        ↓
                  [Send Notifications]
```

## 🚀 Features

### 1. Security Misconfiguration Detection

- Public storage buckets
- Overly permissive IAM policies
- Unencrypted resources
- Non-compliant firewall rules

### 2. Audit Log Analysis

- Suspicious authentication attempts
- Privilege escalation detection
- Unusual API calls
- Resource deletion tracking

### 3. Automated Alerting

- Real-time Pub/Sub notifications
- Email alerts via SendGrid
- Slack webhook integration
- Severity-based routing

### 4. Compliance Reporting

- Daily security posture reports
- Resource inventory
- IAM policy audits
- JSON and PDF report formats

## 📋 Prerequisites

- GCP Account with billing enabled
- `gcloud` CLI installed
- Terraform >= 1.5.0
- Python 3.11+
- Service Account with appropriate permissions

## 🔐 Required IAM Permissions

Create a service account with these roles:

```bash
roles/cloudfunctions.admin
roles/storage.admin
roles/pubsub.admin
roles/logging.viewer
roles/iam.securityReviewer
roles/securitycenter.adminEditor
```

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/learning-google-cloud-platform.git
cd learning-google-cloud-platform
```

### 2. Set Environment Variables

```bash
export PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"
export ALERT_EMAIL="security@yourcompany.com"
```

### 3. Deploy Infrastructure

```bash
cd terraform
terraform init
terraform plan -var="project_id=${PROJECT_ID}"
terraform apply -var="project_id=${PROJECT_ID}"
```

### 4. Deploy Functions

```bash
cd ../functions
gcloud functions deploy security-scanner \
  --runtime python311 \
  --trigger-topic security-scan \
  --entry-point scan_resources \
  --region ${REGION}
```

## 🎮 Usage

### Manual Scan

```bash
gcloud scheduler jobs run security-scan-job --location=${REGION}
```

### View Logs

```bash
gcloud logging read "resource.type=cloud_function" --limit 50
```

### Query BigQuery

```bash
bq query --use_legacy_sql=false '
SELECT timestamp, severity, message 
FROM `security_logs.audit_events` 
WHERE severity = "HIGH" 
ORDER BY timestamp DESC 
LIMIT 10'
```

## 📊 Sample Output

### Security Report

```json
{
  "scan_timestamp": "2025-10-16T10:30:00Z",
  "findings": [
    {
      "severity": "HIGH",
      "resource": "gs://my-bucket",
      "issue": "Bucket is publicly accessible",
      "recommendation": "Remove allUsers from IAM policy"
    }
  ],
  "summary": {
    "total_resources": 47,
    "compliant": 42,
    "non_compliant": 5
  }
}
```

## 🧪 Testing

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Run unit tests
pytest tests/

# Run integration tests
pytest tests/integration/ --project-id=${PROJECT_ID}

# Security scan
bandit -r functions/
```

## 📈 Monitoring

Access the monitoring dashboard:

```bash
echo "https://console.cloud.google.com/monitoring/dashboards/custom/${DASHBOARD_ID}?project=${PROJECT_ID}"
```

## 💰 Cost Estimation

Approximate monthly costs (for small workloads):

- Cloud Functions: $0-5
- Cloud Storage: $1-3
- Pub/Sub: $0-2
- Cloud Logging: $0.50/GB
- **Total**: ~$5-15/month

## 🔒 Security Best Practices Implemented

✅ Least privilege IAM policies  
✅ Encrypted data at rest and in transit  
✅ Service account key rotation  
✅ VPC Service Controls integration  
✅ Audit logging enabled  
✅ Secret Manager for credentials  
✅ Network security hardening

## 🐛 Troubleshooting

### Function fails to deploy

```bash
# Check service account permissions
gcloud projects get-iam-policy ${PROJECT_ID}

# Verify APIs are enabled
gcloud services list --enabled
```

### No alerts received

```bash
# Check Pub/Sub subscription
gcloud pubsub subscriptions list

# Test function manually
gcloud functions call security-scanner --data '{}'
```

## 📚 Learning Resources

- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Cloud Functions Documentation](https://cloud.google.com/functions/docs)
- [Security Command Center](https://cloud.google.com/security-command-center)
- [IAM Overview](https://cloud.google.com/iam/docs/overview)

## 🗺️ Roadmap

- [ ] Integration with Security Command Center
- [ ] Machine learning anomaly detection
- [ ] Kubernetes cluster security scanning
- [ ] Automated remediation actions
- [ ] Custom compliance frameworks
- [ ] Multi-cloud support (AWS, Azure)

## 🤝 Contributing

This is a personal learning project, but suggestions are welcome! Open an issue or submit a pull request.

## 📝 License

MIT License - see LICENSE file for details

## 👤 Author

**[Your Name]**

- Cyber Security Engineer
- Learning GCP through practical implementation
- [LinkedIn](https://linkedin.com/in/yourprofile)
- [GitHub](https://github.com/yourusername)

## 🙏 Acknowledgments

- Google Cloud documentation team
- Cloud Security community
- Open source contributors

-----

**Last Updated**: October 2025  
**Status**: Active Development 🚀
