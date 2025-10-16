# Project Structure

This document outlines the complete structure of the GCP Security Scanner project.

## Directory Layout

```
learning-google-cloud-platform/
│
├── 300/README.md                      # Main documentation
├── PROJECT_STRUCTURE.md               # This file
├── LICENSE                            # MIT License
├── .gitignore                         # Git ignore rules
│
├── functions/                         # Cloud Functions code
│   ├── scanner/                       # Security scanner function
│   │   ├── main.py                    # Main scanner logic
│   │   ├── requirements.txt           # Python dependencies
│   │   └── .gcloudignore             # Deployment ignore file
│   │
│   └── alerts/                        # Alert handler function
│       ├── alert_handler.py           # Alert processing logic
│       ├── requirements.txt           # Python dependencies
│       └── .gcloudignore             # Deployment ignore file
│
├── terraform/                         # Infrastructure as Code
│   ├── main.tf                        # Main Terraform configuration
│   ├── variables.tf                   # Variable definitions
│   ├── outputs.tf                     # Output values
│   ├── versions.tf                    # Provider versions
│   └── terraform.tfvars.example       # Example variables file
│
├── scripts/                           # Utility scripts
│   ├── deploy.sh                      # Deployment script
│   ├── cleanup.sh                     # Resource cleanup script
│   ├── test_scanner.sh                # Scanner testing script
│   └── manual_scan.sh                 # Trigger manual scan
│
├── tests/                             # Test suite
│   ├── unit/                          # Unit tests
│   │   ├── test_scanner.py
│   │   └── test_alerts.py
│   │
│   ├── integration/                   # Integration tests
│   │   ├── test_end_to_end.py
│   │   └── test_pubsub.py
│   │
│   ├── conftest.py                    # Pytest configuration
│   └── requirements-test.txt          # Test dependencies
│
├── docs/                              # Additional documentation
│   ├── ARCHITECTURE.md                # Architecture details
│   ├── SECURITY.md                    # Security considerations
│   ├── DEPLOYMENT.md                  # Deployment guide
│   ├── TROUBLESHOOTING.md             # Common issues
│   └── API_REFERENCE.md               # API documentation
│
├── examples/                          # Usage examples
│   ├── sample_reports/                # Example security reports
│   ├── custom_checks.py               # Custom security checks
│   └── integration_examples/          # Integration samples
│
└── monitoring/                        # Monitoring configuration
    ├── dashboards/                    # Cloud Monitoring dashboards
    │   └── security_dashboard.json
    ├── alerts/                        # Alert policies
    │   └── alert_policies.yaml
    └── slos/                          # Service Level Objectives
        └── scanner_slo.yaml
```

## Key Files Description

### Core Application Files

#### `functions/scanner/main.py`

- Main security scanner implementation
- Scans GCP resources for misconfigurations
- Generates security reports
- Publishes alerts to Pub/Sub
- **Classes**: `SecurityScanner`
- **Entry Point**: `scan_resources()`

#### `functions/alerts/alert_handler.py`

- Processes security alerts
- Routes notifications based on severity
- Formats messages for different channels
- **Classes**: `AlertHandler`
- **Entry Point**: `handle_alert()`

### Infrastructure Files

#### `terraform/main.tf`

- Defines all GCP resources
- Cloud Functions, Storage, Pub/Sub, IAM
- KMS encryption keys
- Cloud Scheduler jobs

#### `scripts/deploy.sh`

- Automated deployment script
- Enables APIs
- Runs Terraform
- Deploys functions
- Validates deployment

### Configuration Files

#### `.gitignore`

```
# Python
__pycache__/
*.py[cod]
*$py.class
.venv/
venv/

# Terraform
.terraform/
*.tfstate
*.tfstate.backup
.terraform.lock.hcl

# GCP
*.json
!terraform/*.json
credentials/
.gcloudignore

# IDE
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db
```

#### `requirements.txt` (Scanner)

```
google-cloud-storage==2.14.0
google-cloud-logging==3.9.0
google-cloud-pubsub==2.19.0
google-cloud-secret-manager==2.18.0
google-cloud-resource-manager==1.11.0
google-api-python-client==2.111.0
functions-framework==3.5.0
```

#### `requirements-test.txt`

```
pytest==7.4.3
pytest-cov==4.1.0
pytest-mock==3.12.0
pytest-asyncio==0.21.1
requests-mock==1.11.0
bandit==1.7.5
black==23.12.1
flake8==6.1.0
mypy==1.7.1
```

## Security Checks Implemented

### Storage Security

- ✅ Public bucket detection
- ✅ Encryption verification (CMEK)
- ✅ Versioning status
- ✅ Lifecycle policies
- ✅ Access logging

### IAM Security

- ✅ Overly permissive roles
- ✅ Public IAM bindings
- ✅ Service account key age
- ✅ Principle of least privilege
- ✅ Organization policy compliance

### Compute Security

- ✅ External IP exposure
- ✅ OS Login configuration
- ✅ Disk encryption (CMEK)
- ✅ Metadata security
- ✅ Shielded VM status

### Network Security

- ✅ Firewall rules (SSH/RDP exposure)
- ✅ VPC configuration
- ✅ Public IP ranges
- ✅ Network tags
- ✅ Load balancer security

### Compliance Checks

- ✅ CIS GCP Foundations Benchmark
- ✅ PCI-DSS relevant controls
- ✅ HIPAA considerations
- ✅ Custom policy framework

## Extending the Scanner

### Adding Custom Checks

1. **Create new check method in `main.py`**:

```python
def check_custom_resource(self):
    """Check custom GCP resources"""
    try:
        # Your custom logic here
        service = discovery.build('service-name', 'v1')
        resources = service.resources().list(project=self.project_id).execute()
        
        for resource in resources.get('items', []):
            # Analyze resource
            if self.is_misconfigured(resource):
                self.findings.append({
                    'severity': 'HIGH',
                    'category': 'Custom',
                    'resource': resource['name'],
                    'issue': 'Custom check failed',
                    'details': 'Description of the issue',
                    'recommendation': 'How to fix it',
                    'timestamp': datetime.utcnow().isoformat()
                })
    except Exception as e:
        self.logger.log_text(f"Error: {str(e)}", severity="ERROR")
```

1. **Add to scan execution in `scan_all_resources()`**:

```python
def scan_all_resources(self):
    self.check_storage_buckets()
    self.check_iam_policies()
    # ... existing checks ...
    self.check_custom_resource()  # Add your check
    
    return self.generate_report()
```

### Custom Alert Handlers

Create new notification channels in `alert_handler.py`:

```python
def send_slack_notification(self, webhook_url: str, findings: List):
    """Send Slack notification"""
    import requests
    
    message = self.format_slack_message(findings)
    response = requests.post(webhook_url, json=message)
    return response.status_code == 200

def send_pagerduty_alert(self, routing_key: str, findings: List):
    """Create PagerDuty incident"""
    import requests
    
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"{len(findings)} security findings",
            "severity": "critical",
            "source": "gcp-security-scanner"
        }
    }
    
    response = requests.post(
        "https://events.pagerduty.com/v2/enqueue",
        json=payload
    )
    return response.status_code == 202
```

## Testing Strategy

### Unit Tests

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=functions --cov-report=html

# Run specific test
pytest tests/unit/test_scanner.py::test_check_storage_buckets
```

### Integration Tests

```bash
# Requires GCP credentials
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"
export TEST_PROJECT_ID="your-test-project"

pytest tests/integration/ -v
```

### Security Tests

```bash
# Static analysis
bandit -r functions/

# Linting
flake8 functions/

# Type checking
mypy functions/
```

## Monitoring and Observability

### Key Metrics

- Scan completion rate
- Finding severity distribution
- Alert delivery success rate
- Function execution time
- Error rates

### Log Queries

**View all security findings**:

```
resource.type="cloud_function"
jsonPayload.alert_type="security_finding"
severity>=WARNING
```

**Function errors**:

```
resource.type="cloud_function"
severity>=ERROR
timestamp>="2025-10-01T00:00:00Z"
```

**High-severity alerts**:

```
resource.type="cloud_function"
jsonPayload.severity="HIGH" OR jsonPayload.severity="CRITICAL"
```

## Cost Optimization

### Estimated Costs (Monthly)

- Cloud Functions: $2-5
- Cloud Storage: $1-3
- Pub/Sub: $0.40-2
- Cloud Logging: $0.50/GB
- Cloud Scheduler: $0.10
- **Total**: ~$5-12/month

### Cost Reduction Tips

1. Adjust scan frequency in Cloud Scheduler
1. Set retention policies on storage buckets
1. Use log exclusion filters
1. Optimize function memory allocation
1. Enable committed use discounts

## Maintenance

### Regular Tasks

- [ ] Review and update security checks monthly
- [ ] Rotate service account keys quarterly
- [ ] Update dependencies (Python packages)
- [ ] Review and archive old reports
- [ ] Test disaster recovery procedures
- [ ] Update Terraform to latest version

### Dependency Updates

```bash
# Update Python packages
pip list --outdated
pip install --upgrade -r requirements.txt

# Update Terraform providers
terraform init -upgrade
```

## Troubleshooting

See `docs/TROUBLESHOOTING.md` for detailed troubleshooting guides.

Common issues:

- Permission denied errors → Check IAM roles
- Function timeout → Increase timeout or optimize code
- No alerts received → Check Pub/Sub subscriptions
- Reports not saved → Verify bucket permissions

## Additional Resources

- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Cloud Functions Documentation](https://cloud.google.com/functions/docs)
- [Terraform GCP Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [Python Client Libraries](https://cloud.google.com/python/docs/reference)

-----

**Maintained by**: [Your Name]  
**Last Updated**: October 2025  
**Version**: 1.0.0
