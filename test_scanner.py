“””
Unit tests for the GCP Security Scanner
Tests security checks and report generation
“””

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, call
from google.cloud import storage

class TestSecurityScanner:
“”“Test suite for SecurityScanner class”””

```
@pytest.fixture
def mock_clients(self):
    """Mock GCP client libraries"""
    with patch('main.storage_client') as mock_storage, \
         patch('main.logging_client') as mock_logging, \
         patch('main.pubsub_client') as mock_pubsub:
        
        # Mock logger
        mock_logger = MagicMock()
        mock_logging.logger.return_value = mock_logger
        
        yield {
            'storage': mock_storage,
            'logging': mock_logging,
            'pubsub': mock_pubsub,
            'logger': mock_logger
        }

@pytest.fixture
def scanner(self, mock_clients):
    """Create scanner instance with mocked dependencies"""
    from main import SecurityScanner
    return SecurityScanner(project_id='test-project')

def test_scanner_initialization(self, scanner):
    """Test scanner initializes correctly"""
    assert scanner.project_id == 'test-project'
    assert scanner.findings == []
    assert scanner.logger is not None

def test_check_storage_buckets_public_access(self, scanner, mock_clients):
    """Test detection of publicly accessible buckets"""
    # Mock bucket with public access
    mock_bucket = MagicMock()
    mock_bucket.name = 'test-bucket'
    mock_bucket.default_kms_key_name = None
    mock_bucket.versioning_enabled = True
    
    # Mock IAM policy with public access
    mock_policy = MagicMock()
    mock_policy.bindings = [
        {
            'role': 'roles/storage.objectViewer',
            'members': ['allUsers']
        }
    ]
    mock_bucket.get_iam_policy.return_value = mock_policy
    
    mock_clients['storage'].list_buckets.return_value = [mock_bucket]
    
    # Execute check
    scanner.check_storage_buckets()
    
    # Verify findings
    assert len(scanner.findings) == 2  # Public access + no CMEK
    
    public_access_finding = next(
        (f for f in scanner.findings if 'public access' in f['issue'].lower()),
        None
    )
    
    assert public_access_finding is not None
    assert public_access_finding['severity'] == 'HIGH'
    assert public_access_finding['category'] == 'Storage'
    assert 'gs://test-bucket' in public_access_finding['resource']

def test_check_storage_buckets_no_encryption(self, scanner, mock_clients):
    """Test detection of unencrypted buckets"""
    mock_bucket = MagicMock()
    mock_bucket.name = 'unencrypted-bucket'
    mock_bucket.default_kms_key_name = None
    mock_bucket.versioning_enabled = True
    
    mock_policy = MagicMock()
    mock_policy.bindings = []
    mock_bucket.get_iam_policy.return_value = mock_policy
    
    mock_clients['storage'].list_buckets.return_value = [mock_bucket]
    
    scanner.check_storage_buckets()
    
    encryption_finding = next(
        (f for f in scanner.findings if 'encryption' in f['issue'].lower()),
        None
    )
    
    assert encryption_finding is not None
    assert encryption_finding['severity'] == 'MEDIUM'
    assert 'CMEK' in encryption_finding['recommendation']

def test_check_storage_buckets_no_versioning(self, scanner, mock_clients):
    """Test detection of buckets without versioning"""
    mock_bucket = MagicMock()
    mock_bucket.name = 'no-version-bucket'
    mock_bucket.default_kms_key_name = 'projects/test/locations/us/keyRings/kr/cryptoKeys/key'
    mock_bucket.versioning_enabled = False
    
    mock_policy = MagicMock()
    mock_policy.bindings = []
    mock_bucket.get_iam_policy.return_value = mock_policy
    
    mock_clients['storage'].list_buckets.return_value = [mock_bucket]
    
    scanner.check_storage_buckets()
    
    versioning_finding = next(
        (f for f in scanner.findings if 'versioning' in f['issue'].lower()),
        None
    )
    
    assert versioning_finding is not None
    assert versioning_finding['severity'] == 'LOW'

@patch('main.discovery.build')
def test_check_iam_policies_dangerous_roles(self, mock_discovery, scanner):
    """Test detection of overly permissive IAM roles"""
    mock_service = MagicMock()
    mock_discovery.return_value = mock_service
    
    mock_policy = {
        'bindings': [
            {
                'role': 'roles/owner',
                'members': ['user:test@example.com']
            },
            {
                'role': 'roles/editor',
                'members': ['user:another@example.com']
            }
        ]
    }
    
    mock_service.projects().getIamPolicy().execute.return_value = mock_policy
    
    scanner.check_iam_policies()
    
    # Should find 2 dangerous role assignments
    dangerous_findings = [
        f for f in scanner.findings 
        if f['category'] == 'IAM' and 'privileged role' in f['issue']
    ]
    
    assert len(dangerous_findings) == 2
    assert all(f['severity'] == 'MEDIUM' for f in dangerous_findings)

@patch('main.discovery.build')
def test_check_iam_policies_public_binding(self, mock_discovery, scanner):
    """Test detection of public IAM bindings"""
    mock_service = MagicMock()
    mock_discovery.return_value = mock_service
    
    mock_policy = {
        'bindings': [
            {
                'role': 'roles/viewer',
                'members': ['allUsers']
            }
        ]
    }
    
    mock_service.projects().getIamPolicy().execute.return_value = mock_policy
    
    scanner.check_iam_policies()
    
    public_finding = next(
        (f for f in scanner.findings if 'public' in f['issue'].lower()),
        None
    )
    
    assert public_finding is not None
    assert public_finding['severity'] == 'CRITICAL'
    assert 'Remove public access' in public_finding['recommendation']

@patch('main.discovery.build')
def test_check_firewall_rules_ssh_exposure(self, mock_discovery, scanner):
    """Test detection of SSH exposed to internet"""
    mock_service = MagicMock()
    mock_discovery.return_value = mock_service
    
    mock_firewalls = {
        'items': [
            {
                'name': 'allow-ssh',
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ]
            }
        ]
    }
    
    mock_service.firewalls().list().execute.return_value = mock_firewalls
    
    scanner.check_firewall_rules()
    
    ssh_finding = next(
        (f for f in scanner.findings if 'SSH' in f['issue']),
        None
    )
    
    assert ssh_finding is not None
    assert ssh_finding['severity'] == 'HIGH'
    assert ssh_finding['category'] == 'Network'

@patch('main.discovery.build')
def test_check_firewall_rules_rdp_exposure(self, mock_discovery, scanner):
    """Test detection of RDP exposed to internet"""
    mock_service = MagicMock()
    mock_discovery.return_value = mock_service
    
    mock_firewalls = {
        'items': [
            {
                'name': 'allow-rdp',
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['3389']
                    }
                ]
            }
        ]
    }
    
    mock_service.firewalls().list().execute.return_value = mock_firewalls
    
    scanner.check_firewall_rules()
    
    rdp_finding = next(
        (f for f in scanner.findings if 'RDP' in f['issue']),
        None
    )
    
    assert rdp_finding is not None
    assert rdp_finding['severity'] == 'HIGH'

def test_generate_report(self, scanner):
    """Test report generation with findings"""
    scanner.findings = [
        {
            'severity': 'HIGH',
            'category': 'Storage',
            'resource': 'gs://test-bucket',
            'issue': 'Test issue',
            'details': 'Test details',
            'recommendation': 'Test recommendation',
            'timestamp': datetime.utcnow().isoformat()
        },
        {
            'severity': 'MEDIUM',
            'category': 'IAM',
            'resource': 'project/test',
            'issue': 'Another issue',
            'details': 'More details',
            'recommendation': 'Fix it',
            'timestamp': datetime.utcnow().isoformat()
        }
    ]
    
    report = scanner.generate_report()
    
    assert report['project_id'] == 'test-project'
    assert 'scan_timestamp' in report
    assert report['summary']['total_findings'] == 2
    assert report['summary']['high'] == 1
    assert report['summary']['medium'] == 1
    assert len(report['findings']) == 2

def test_generate_report_empty_findings(self, scanner):
    """Test report generation with no findings"""
    report = scanner.generate_report()
    
    assert report['summary']['total_findings'] == 0
    assert report['summary']['critical'] == 0
    assert report['summary']['high'] == 0
    assert report['findings'] == []

def test_save_report(self, scanner, mock_clients):
    """Test saving report to Cloud Storage"""
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    
    mock_clients['storage'].bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    
    report = {
        'scan_timestamp': datetime.utcnow().isoformat(),
        'project_id': 'test-project',
        'summary': {'total_findings': 0},
        'findings': []
    }
    
    scanner.save_report(report)
    
    # Verify bucket and blob creation
    mock_clients['storage'].bucket.assert_called_once()
    mock_bucket.blob.assert_called_once()
    mock_blob.upload_from_string.assert_called_once()
    
    # Verify JSON content
    call_args = mock_blob.upload_from_string.call_args
    uploaded_data = call_args[0][0]
    assert json.loads(uploaded_data) == report

def test_send_alerts_high_severity(self, scanner, mock_clients):
    """Test sending alerts for high severity findings"""
    scanner.findings = [
        {
            'severity': 'CRITICAL',
            'category': 'IAM',
            'resource': 'project/test',
            'issue': 'Critical issue',
            'details': 'Very bad',
            'recommendation': 'Fix immediately',
            'timestamp': datetime.utcnow().isoformat()
        },
        {
            'severity': 'HIGH',
            'category': 'Network',
            'resource': 'firewall/rule',
            'issue': 'High severity issue',
            'details': 'Bad config',
            'recommendation': 'Fix soon',
            'timestamp': datetime.utcnow().isoformat()
        }
    ]
    
    mock_future = MagicMock()
    mock_future.result.return_value = 'message-id-123'
    mock_clients['pubsub'].publish.return_value = mock_future
    
    scanner.send_alerts()
    
    # Verify Pub/Sub publish was called
    mock_clients['pubsub'].publish.assert_called_once()
    
    # Verify message contains both findings
    call_args = mock_clients['pubsub'].publish.call_args
    message_data = json.loads(call_args[0][1].decode())
    
    assert message_data['alert_type'] == 'security_finding'
    assert message_data['findings_count'] == 2
    assert len(message_data['findings']) == 2

def test_send_alerts_no_high_severity(self, scanner, mock_clients):
    """Test no alerts sent for low severity findings"""
    scanner.findings = [
        {
            'severity': 'LOW',
            'category': 'Storage',
            'resource': 'gs://bucket',
            'issue': 'Low severity',
            'details': 'Not urgent',
            'recommendation': 'Consider fixing',
            'timestamp': datetime.utcnow().isoformat()
        }
    ]
    
    scanner.send_alerts()
    
    # Verify no Pub/Sub publish
    mock_clients['pubsub'].publish.assert_not_called()

def test_scan_all_resources_integration(self, scanner, mock_clients):
    """Test complete scan workflow"""
    # Mock empty results for all checks
    mock_clients['storage'].list_buckets.return_value = []
    
    with patch('main.discovery.build') as mock_discovery:
        mock_service = MagicMock()
        mock_discovery.return_value = mock_service
        
        # Mock empty IAM policy
        mock_service.projects().getIamPolicy().execute.return_value = {
            'bindings': []
        }
        
        # Mock empty compute zones
        mock_service.zones().list().execute.return_value = {'items': []}
        
        # Mock empty firewalls
        mock_service.firewalls().list().execute.return_value = {'items': []}
        
        # Mock empty service accounts
        mock_service.projects().serviceAccounts().list().execute.return_value = {
            'accounts': []
        }
        
        # Mock bucket for saving report
        mock_bucket = MagicMock()
        mock_blob = MagicMock()
        mock_clients['storage'].bucket.return_value = mock_bucket
        mock_bucket.blob.return_value = mock_blob
        
        # Run full scan
        report = scanner.scan_all_resources()
        
        # Verify report structure
        assert 'scan_timestamp' in report
        assert 'project_id' in report
        assert 'summary' in report
        assert 'findings' in report
        
        # Verify report was saved
        mock_blob.upload_from_string.assert_called_once()
```

class TestCloudFunctionEntry:
“”“Test Cloud Function entry points”””

```
@patch('main.SecurityScanner')
def test_scan_resources_success(self, mock_scanner_class):
    """Test successful scan_resources invocation"""
    from main import scan_resources
    
    # Mock cloud event
    mock_event = MagicMock()
    mock_event.data = {
        'message': {
            'data': 'eyJwcm9qZWN0X2lkIjogInRlc3QtcHJvamVjdCJ9'  # base64 encoded JSON
        }
    }
    
    # Mock scanner instance
    mock_scanner = MagicMock()
    mock_scanner.scan_all_resources.return_value = {
        'scan_timestamp': '2025-10-16T10:00:00Z',
        'summary': {'total_findings': 5}
    }
    mock_scanner_class.return_value = mock_scanner
    
    # Execute function
    result = scan_resources(mock_event)
    
    # Verify results
    assert result['status'] == 'success'
    assert result['findings_count'] == 5
    mock_scanner.scan_all_resources.assert_called_once()

@patch('main.SecurityScanner')
def test_scan_resources_error_handling(self, mock_scanner_class):
    """Test error handling in scan_resources"""
    from main import scan_resources
    
    mock_event = MagicMock()
    mock_event.data = {
        'message': {
            'data': 'eyJwcm9qZWN0X2lkIjogInRlc3QtcHJvamVjdCJ9'
        }
    }
    
    # Mock scanner to raise exception
    mock_scanner = MagicMock()
    mock_scanner.scan_all_resources.side_effect = Exception("Test error")
    mock_scanner_class.return_value = mock_scanner
    
    # Execute function
    result = scan_resources(mock_event)
    
    # Verify error response
    assert result['status'] == 'error'
    assert 'Test error' in result['message']
```

if **name** == ‘**main**’:
pytest.main([**file**, ‘-v’, ‘–cov=main’, ‘–cov-report=html’])
