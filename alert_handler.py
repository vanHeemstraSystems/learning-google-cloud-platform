“””
Alert Handler - Cloud Function
Processes security alerts and sends notifications
“””

import json
import base64
from datetime import datetime
from typing import Dict, Any, List
from google.cloud import logging
import functions_framework

# Initialize logging

logging_client = logging.Client()
logger = logging_client.logger(‘alert-handler’)

class AlertHandler:
“”“Handles security alert notifications”””

```
def __init__(self, alert_data: Dict[str, Any]):
    self.alert_data = alert_data
    self.findings = alert_data.get('findings', [])
    self.timestamp = alert_data.get('timestamp', datetime.utcnow().isoformat())

def process_alerts(self):
    """Process and route alerts based on severity"""
    logger.log_text(
        f"Processing {len(self.findings)} security findings",
        severity="INFO"
    )
    
    # Categorize findings by severity
    critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
    high = [f for f in self.findings if f['severity'] == 'HIGH']
    
    # Log all alerts
    self.log_alerts()
    
    # Send notifications
    if critical:
        self.send_critical_alert(critical)
    
    if high:
        self.send_high_alert(high)
    
    return {
        'processed': len(self.findings),
        'critical': len(critical),
        'high': len(high)
    }

def log_alerts(self):
    """Log alerts to Cloud Logging"""
    for finding in self.findings:
        severity = finding.get('severity', 'INFO')
        message = (
            f"Security Finding: {finding['issue']} | "
            f"Resource: {finding['resource']} | "
            f"Category: {finding['category']}"
        )
        
        logger.log_struct(
            {
                'message': message,
                'finding': finding,
                'alert_type': 'security_finding'
            },
            severity=severity
        )

def send_critical_alert(self, findings: List[Dict[str, Any]]):
    """Send immediate notification for critical findings"""
    logger.log_text(
        f"CRITICAL ALERT: {len(findings)} critical security issues detected",
        severity="CRITICAL"
    )
    
    # Format alert message
    alert_summary = self.format_alert_summary(findings, 'CRITICAL')
    
    # In production, integrate with:
    # - SendGrid for email
    # - Slack webhook
    # - PagerDuty for on-call
    # - SMS via Twilio
    
    logger.log_struct(
        {
            'alert_type': 'critical_security_alert',
            'findings_count': len(findings),
            'summary': alert_summary,
            'requires_immediate_action': True
        },
        severity="CRITICAL"
    )

def send_high_alert(self, findings: List[Dict[str, Any]]):
    """Send notification for high severity findings"""
    logger.log_text(
        f"HIGH PRIORITY: {len(findings)} high-severity security issues detected",
        severity="WARNING"
    )
    
    alert_summary = self.format_alert_summary(findings, 'HIGH')
    
    logger.log_struct(
        {
            'alert_type': 'high_priority_security_alert',
            'findings_count': len(findings),
            'summary': alert_summary,
            'requires_action': True
        },
        severity="WARNING"
    )

def format_alert_summary(self, findings: List[Dict[str, Any]], severity: str) -> str:
    """Format findings into readable summary"""
    summary_parts = [
        f"\n{'='*60}",
        f"SECURITY ALERT - {severity} SEVERITY",
        f"Timestamp: {self.timestamp}",
        f"Total Findings: {len(findings)}",
        f"{'='*60}\n"
    ]
    
    for idx, finding in enumerate(findings, 1):
        summary_parts.extend([
            f"\n{idx}. {finding['issue']}",
            f"   Resource: {finding['resource']}",
            f"   Category: {finding['category']}",
            f"   Details: {finding['details']}",
            f"   Recommendation: {finding['recommendation']}"
        ])
    
    summary_parts.append(f"\n{'='*60}\n")
    
    return '\n'.join(summary_parts)

def format_slack_message(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format message for Slack webhook"""
    severity_emoji = {
        'CRITICAL': ':rotating_light:',
        'HIGH': ':warning:',
        'MEDIUM': ':large_orange_diamond:',
        'LOW': ':information_source:'
    }
    
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity_emoji.get('CRITICAL', '')} Security Alert Detected"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{len(findings)}* security findings require attention"
            }
        }
    ]
    
    for finding in findings[:5]:  # Show first 5
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{finding['issue']}*\n"
                    f"Resource: `{finding['resource']}`\n"
                    f"Severity: {severity_emoji.get(finding['severity'], '')} {finding['severity']}"
                )
            }
        })
    
    return {"blocks": blocks}

def format_email_html(self, findings: List[Dict[str, Any]]) -> str:
    """Format HTML email body"""
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#17a2b8'
    }
    
    html_parts = [
        '<html><body style="font-family: Arial, sans-serif;">',
        '<h2 style="color: #dc3545;">Security Alert</h2>',
        f'<p>Security scan detected <strong>{len(findings)}</strong> issues requiring attention.</p>',
        '<hr>'
    ]
    
    for finding in findings:
        color = severity_colors.get(finding['severity'], '#6c757d')
        html_parts.extend([
            '<div style="margin: 20px 0; padding: 15px; border-left: 4px solid {color}; background-color: #f8f9fa;">',
            f'<h3 style="color: {color}; margin-top: 0;">{finding["issue"]}</h3>',
            f'<p><strong>Resource:</strong> <code>{finding["resource"]}</code></p>',
            f'<p><strong>Category:</strong> {finding["category"]}</p>',
            f'<p><strong>Details:</strong> {finding["details"]}</p>',
            f'<p><strong>Recommendation:</strong> {finding["recommendation"]}</p>',
            '</div>'
        ])
    
    html_parts.extend([
        '<hr>',
        f'<p style="color: #6c757d; font-size: 12px;">Generated at {self.timestamp}</p>',
        '</body></html>'
    ])
    
    return '\n'.join(html_parts)
```

@functions_framework.cloud_event
def handle_alert(cloud_event):
“””
Cloud Function entry point for alert handling
Triggered by Pub/Sub messages from security scanner
“””
try:
# Decode Pub/Sub message
message_data = base64.b64decode(cloud_event.data[“message”][“data”]).decode()
alert_data = json.loads(message_data)

```
    # Process alerts
    handler = AlertHandler(alert_data)
    result = handler.process_alerts()
    
    return {
        'status': 'success',
        'processed_findings': result['processed'],
        'critical_alerts': result['critical'],
        'high_priority_alerts': result['high']
    }

except Exception as e:
    error_msg = f"Alert handling failed: {str(e)}"
    logger.log_text(error_msg, severity="ERROR")
    return {'status': 'error', 'message': error_msg}
```

# Optional: HTTP endpoint for testing

@functions_framework.http
def test_alert(request):
“”“Test endpoint for alert handler”””
try:
request_json = request.get_json(silent=True)

```
    if not request_json:
        return {'error': 'No JSON payload provided'}, 400
    
    handler = AlertHandler(request_json)
    result = handler.process_alerts()
    
    return {'status': 'success', 'result': result}, 200

except Exception as e:
    return {'status': 'error', 'message': str(e)}, 500
```
