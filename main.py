“””
GCP Security Scanner - Cloud Function
Scans GCP resources for security misconfigurations and compliance issues
“””

import json
import base64
from datetime import datetime
from typing import Dict, List, Any
from google.cloud import storage, logging, pubsub_v1, secretmanager
from google.cloud import resource_manager_v3
from googleapiclient import discovery
import functions_framework

# Initialize clients

storage_client = storage.Client()
logging_client = logging.Client()
pubsub_client = pubsub_v1.PublisherClient()
secret_client = secretmanager.SecretManagerServiceClient()

class SecurityScanner:
“”“Main security scanner class”””

```
def __init__(self, project_id: str):
    self.project_id = project_id
    self.findings = []
    self.logger = logging_client.logger('security-scanner')
    
def scan_all_resources(self) -> Dict[str, Any]:
    """Execute all security checks"""
    self.logger.log_text(f"Starting security scan for project: {self.project_id}", severity="INFO")
    
    # Run all security checks
    self.check_storage_buckets()
    self.check_iam_policies()
    self.check_compute_instances()
    self.check_firewall_rules()
    self.check_service_accounts()
    
    # Generate report
    report = self.generate_report()
    self.save_report(report)
    
    # Send alerts for high severity findings
    self.send_alerts()
    
    return report

def check_storage_buckets(self):
    """Check Cloud Storage buckets for security issues"""
    self.logger.log_text("Scanning storage buckets...", severity="INFO")
    
    buckets = storage_client.list_buckets(project=self.project_id)
    
    for bucket in buckets:
        # Check for public access
        iam_policy = bucket.get_iam_policy()
        
        for binding in iam_policy.bindings:
            if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                self.findings.append({
                    'severity': 'HIGH',
                    'category': 'Storage',
                    'resource': f'gs://{bucket.name}',
                    'issue': 'Bucket has public access',
                    'details': f"IAM binding allows public access with role: {binding['role']}",
                    'recommendation': 'Remove allUsers and allAuthenticatedUsers from IAM policy',
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Check for encryption
        if not bucket.default_kms_key_name:
            self.findings.append({
                'severity': 'MEDIUM',
                'category': 'Storage',
                'resource': f'gs://{bucket.name}',
                'issue': 'Bucket not encrypted with CMEK',
                'details': 'Using Google-managed encryption keys instead of customer-managed keys',
                'recommendation': 'Enable Customer-Managed Encryption Keys (CMEK)',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Check for versioning
        if not bucket.versioning_enabled:
            self.findings.append({
                'severity': 'LOW',
                'category': 'Storage',
                'resource': f'gs://{bucket.name}',
                'issue': 'Versioning not enabled',
                'details': 'Object versioning is disabled',
                'recommendation': 'Enable versioning for data recovery',
                'timestamp': datetime.utcnow().isoformat()
            })

def check_iam_policies(self):
    """Check IAM policies for overly permissive access"""
    self.logger.log_text("Analyzing IAM policies...", severity="INFO")
    
    try:
        crm_service = discovery.build('cloudresourcemanager', 'v1')
        policy = crm_service.projects().getIamPolicy(
            resource=self.project_id,
            body={}
        ).execute()
        
        dangerous_roles = [
            'roles/owner',
            'roles/editor',
            'roles/iam.securityAdmin'
        ]
        
        for binding in policy.get('bindings', []):
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            # Check for overly permissive roles
            if role in dangerous_roles:
                for member in members:
                    if member.startswith('user:'):
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'category': 'IAM',
                            'resource': f'project/{self.project_id}',
                            'issue': f'User has privileged role: {role}',
                            'details': f"Member {member} has broad permissions",
                            'recommendation': 'Apply principle of least privilege, use custom roles',
                            'timestamp': datetime.utcnow().isoformat()
                        })
            
            # Check for public bindings
            if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                self.findings.append({
                    'severity': 'CRITICAL',
                    'category': 'IAM',
                    'resource': f'project/{self.project_id}',
                    'issue': 'Public IAM binding detected',
                    'details': f"Role {role} is granted to public",
                    'recommendation': 'Remove public access immediately',
                    'timestamp': datetime.utcnow().isoformat()
                })
    
    except Exception as e:
        self.logger.log_text(f"Error checking IAM policies: {str(e)}", severity="ERROR")

def check_compute_instances(self):
    """Check Compute Engine instances for security issues"""
    self.logger.log_text("Scanning compute instances...", severity="INFO")
    
    try:
        compute = discovery.build('compute', 'v1')
        
        # Get all zones
        zones_result = compute.zones().list(project=self.project_id).execute()
        zones = [zone['name'] for zone in zones_result.get('items', [])]
        
        for zone in zones:
            instances = compute.instances().list(
                project=self.project_id,
                zone=zone
            ).execute()
            
            for instance in instances.get('items', []):
                instance_name = instance['name']
                
                # Check for external IP
                for interface in instance.get('networkInterfaces', []):
                    if 'accessConfigs' in interface:
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Compute',
                            'resource': f'instance/{instance_name}',
                            'issue': 'Instance has external IP',
                            'details': 'VM is directly accessible from internet',
                            'recommendation': 'Use Cloud NAT or VPN for external access',
                            'timestamp': datetime.utcnow().isoformat()
                        })
                
                # Check for OS Login
                metadata = instance.get('metadata', {})
                items = metadata.get('items', [])
                os_login_enabled = any(
                    item.get('key') == 'enable-oslogin' and item.get('value') == 'TRUE'
                    for item in items
                )
                
                if not os_login_enabled:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'category': 'Compute',
                        'resource': f'instance/{instance_name}',
                        'issue': 'OS Login not enabled',
                        'details': 'Using SSH keys instead of OS Login',
                        'recommendation': 'Enable OS Login for better access management',
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                # Check for disk encryption
                for disk in instance.get('disks', []):
                    if 'diskEncryptionKey' not in disk:
                        self.findings.append({
                            'severity': 'LOW',
                            'category': 'Compute',
                            'resource': f'instance/{instance_name}',
                            'issue': 'Disk not encrypted with CMEK',
                            'details': 'Using Google-managed encryption',
                            'recommendation': 'Consider CMEK for sensitive data',
                            'timestamp': datetime.utcnow().isoformat()
                        })
    
    except Exception as e:
        self.logger.log_text(f"Error checking compute instances: {str(e)}", severity="ERROR")

def check_firewall_rules(self):
    """Check VPC firewall rules for security issues"""
    self.logger.log_text("Analyzing firewall rules...", severity="INFO")
    
    try:
        compute = discovery.build('compute', 'v1')
        
        firewalls = compute.firewalls().list(project=self.project_id).execute()
        
        for firewall in firewalls.get('items', []):
            firewall_name = firewall['name']
            
            # Check for overly permissive rules
            if '0.0.0.0/0' in firewall.get('sourceRanges', []):
                allowed = firewall.get('allowed', [])
                
                for rule in allowed:
                    protocol = rule.get('IPProtocol', '')
                    ports = rule.get('ports', ['all'])
                    
                    if protocol == 'tcp' and ('22' in ports or 'all' in ports):
                        self.findings.append({
                            'severity': 'HIGH',
                            'category': 'Network',
                            'resource': f'firewall/{firewall_name}',
                            'issue': 'SSH open to internet',
                            'details': 'Port 22 accessible from 0.0.0.0/0',
                            'recommendation': 'Restrict SSH access to specific IP ranges',
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    
                    if protocol == 'tcp' and ('3389' in ports or 'all' in ports):
                        self.findings.append({
                            'severity': 'HIGH',
                            'category': 'Network',
                            'resource': f'firewall/{firewall_name}',
                            'issue': 'RDP open to internet',
                            'details': 'Port 3389 accessible from 0.0.0.0/0',
                            'recommendation': 'Restrict RDP access to specific IP ranges',
                            'timestamp': datetime.utcnow().isoformat()
                        })
    
    except Exception as e:
        self.logger.log_text(f"Error checking firewall rules: {str(e)}", severity="ERROR")

def check_service_accounts(self):
    """Check service accounts for security issues"""
    self.logger.log_text("Auditing service accounts...", severity="INFO")
    
    try:
        iam_service = discovery.build('iam', 'v1')
        
        service_accounts = iam_service.projects().serviceAccounts().list(
            name=f'projects/{self.project_id}'
        ).execute()
        
        for sa in service_accounts.get('accounts', []):
            sa_email = sa['email']
            
            # Check for user-managed keys
            keys = iam_service.projects().serviceAccounts().keys().list(
                name=f"projects/{self.project_id}/serviceAccounts/{sa_email}",
                keyTypes='USER_MANAGED'
            ).execute()
            
            for key in keys.get('keys', []):
                # Check key age
                valid_after = key.get('validAfterTime', '')
                if valid_after:
                    key_date = datetime.fromisoformat(valid_after.replace('Z', '+00:00'))
                    age_days = (datetime.now(key_date.tzinfo) - key_date).days
                    
                    if age_days > 90:
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'category': 'IAM',
                            'resource': f'serviceAccount/{sa_email}',
                            'issue': f'Service account key is {age_days} days old',
                            'details': 'Key rotation recommended',
                            'recommendation': 'Rotate service account keys every 90 days',
                            'timestamp': datetime.utcnow().isoformat()
                        })
    
    except Exception as e:
        self.logger.log_text(f"Error checking service accounts: {str(e)}", severity="ERROR")

def generate_report(self) -> Dict[str, Any]:
    """Generate security scan report"""
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    for finding in self.findings:
        severity = finding.get('severity', 'LOW')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    report = {
        'scan_timestamp': datetime.utcnow().isoformat(),
        'project_id': self.project_id,
        'summary': {
            'total_findings': len(self.findings),
            'critical': severity_counts['CRITICAL'],
            'high': severity_counts['HIGH'],
            'medium': severity_counts['MEDIUM'],
            'low': severity_counts['LOW']
        },
        'findings': self.findings
    }
    
    return report

def save_report(self, report: Dict[str, Any]):
    """Save report to Cloud Storage"""
    try:
        bucket_name = f"{self.project_id}-security-reports"
        bucket = storage_client.bucket(bucket_name)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        blob_name = f"security-scan-{timestamp}.json"
        blob = bucket.blob(blob_name)
        
        blob.upload_from_string(
            json.dumps(report, indent=2),
            content_type='application/json'
        )
        
        self.logger.log_text(f"Report saved to gs://{bucket_name}/{blob_name}", severity="INFO")
    
    except Exception as e:
        self.logger.log_text(f"Error saving report: {str(e)}", severity="ERROR")

def send_alerts(self):
    """Send alerts for high severity findings"""
    high_severity = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
    
    if not high_severity:
        self.logger.log_text("No high-severity findings to alert on", severity="INFO")
        return
    
    try:
        topic_path = pubsub_client.topic_path(self.project_id, 'security-alerts')
        
        alert_message = {
            'alert_type': 'security_finding',
            'timestamp': datetime.utcnow().isoformat(),
            'findings_count': len(high_severity),
            'findings': high_severity
        }
        
        message_bytes = json.dumps(alert_message).encode('utf-8')
        future = pubsub_client.publish(topic_path, message_bytes)
        
        self.logger.log_text(f"Alert published: {future.result()}", severity="WARNING")
    
    except Exception as e:
        self.logger.log_text(f"Error sending alerts: {str(e)}", severity="ERROR")
```

@functions_framework.cloud_event
def scan_resources(cloud_event):
“””
Cloud Function entry point
Triggered by Pub/Sub message from Cloud Scheduler
“””
try:
# Decode Pub/Sub message
message_data = base64.b64decode(cloud_event.data[“message”][“data”]).decode()
config = json.loads(message_data) if message_data else {}

```
    project_id = config.get('project_id') or 'your-project-id'
    
    # Initialize and run scanner
    scanner = SecurityScanner(project_id)
    report = scanner.scan_all_resources()
    
    return {
        'status': 'success',
        'findings_count': report['summary']['total_findings'],
        'scan_timestamp': report['scan_timestamp']
    }

except Exception as e:
    error_msg = f"Security scan failed: {str(e)}"
    print(error_msg)
    return {'status': 'error', 'message': error_msg}
```
