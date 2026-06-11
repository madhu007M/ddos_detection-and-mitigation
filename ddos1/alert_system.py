import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
from telegram import Bot
import asyncio
import logging
from datetime import datetime
from typing import List, Dict
import json

class AlertSystem:
    def __init__(self, config_path='config.json'):
        self.config = self.load_config(config_path)
        self.logger = logging.getLogger(__name__)
        
        # Initialize services
        self.setup_email()
        self.setup_sms()
        self.setup_telegram()
    
    def load_config(self, path):
        """Load configuration from file"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'email': {
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'sender_email': 'your-email@gmail.com',
                    'sender_password': 'your-app-password',
                    'recipients': ['admin@example.com']
                },
                'sms': {
                    'twilio_account_sid': 'your-account-sid',
                    'twilio_auth_token': 'your-auth-token',
                    'twilio_phone': '+1234567890',
                    'recipients': ['+1234567890']
                },
                'telegram': {
                    'bot_token': 'your-bot-token',
                    'chat_ids': ['your-chat-id']
                },
                'alert_thresholds': {
                    'critical': 90,
                    'high': 70,
                    'medium': 50,
                    'low': 30
                }
            }
    
    def setup_email(self):
        """Setup email configuration"""
        email_config = self.config.get('email', {})
        self.smtp_server = email_config.get('smtp_server')
        self.smtp_port = email_config.get('smtp_port')
        self.sender_email = email_config.get('sender_email')
        self.sender_password = email_config.get('sender_password')
        self.email_recipients = email_config.get('recipients', [])
    
    def setup_sms(self):
        """Setup SMS/Twilio configuration"""
        sms_config = self.config.get('sms', {})
        try:
            self.twilio_client = Client(
                sms_config.get('twilio_account_sid'),
                sms_config.get('twilio_auth_token')
            )
            self.twilio_phone = sms_config.get('twilio_phone')
            self.sms_recipients = sms_config.get('recipients', [])
        except Exception as e:
            self.logger.error(f"Failed to setup Twilio: {e}")
            self.twilio_client = None
    
    def setup_telegram(self):
        """Setup Telegram bot configuration"""
        telegram_config = self.config.get('telegram', {})
        try:
            self.telegram_bot = Bot(token=telegram_config.get('bot_token'))
            self.telegram_chat_ids = telegram_config.get('chat_ids', [])
        except Exception as e:
            self.logger.error(f"Failed to setup Telegram: {e}")
            self.telegram_bot = None
    
    def send_email_alert(self, subject: str, body: str, severity: str = 'medium'):
        """Send email alert"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{severity.upper()}] {subject}"
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.email_recipients)
            
            # Create HTML email
            html = f"""
            <html>
                <head>
                    <style>
                        .alert-box {{
                            padding: 20px;
                            border-radius: 5px;
                            margin: 20px 0;
                        }}
                        .critical {{ background-color: #ff4444; color: white; }}
                        .high {{ background-color: #ff8800; color: white; }}
                        .medium {{ background-color: #ffbb33; color: white; }}
                        .low {{ background-color: #00C851; color: white; }}
                    </style>
                </head>
                <body>
                    <div class="alert-box {severity}">
                        <h2>🚨 DDoS Detection Alert</h2>
                        <h3>{subject}</h3>
                        <p>{body}</p>
                        <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Severity:</strong> {severity.upper()}</p>
                    </div>
                    <hr>
                    <p>This is an automated alert from the DDoS Detection System.</p>
                    <p>Please log in to the dashboard for more details.</p>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent: {subject}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return False
    
    def send_sms_alert(self, message: str, severity: str = 'medium'):
        """Send SMS alert via Twilio"""
        if not self.twilio_client:
            self.logger.warning("Twilio not configured")
            return False
        
        try:
            full_message = f"[{severity.upper()}] DDoS Alert: {message}"
            
            for recipient in self.sms_recipients:
                self.twilio_client.messages.create(
                    body=full_message,
                    from_=self.twilio_phone,
                    to=recipient
                )
            
            self.logger.info(f"SMS alert sent: {message}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send SMS: {e}")
            return False
    
    async def send_telegram_alert(self, message: str, severity: str = 'medium'):
        """Send Telegram alert"""
        if not self.telegram_bot:
            self.logger.warning("Telegram not configured")
            return False
        
        try:
            emoji_map = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            emoji = emoji_map.get(severity, '⚪')
            full_message = f"{emoji} *[{severity.upper()}] DDoS Alert*\n\n{message}\n\n_Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
            
            for chat_id in self.telegram_chat_ids:
                await self.telegram_bot.send_message(
                    chat_id=chat_id,
                    text=full_message,
                    parse_mode='Markdown'
                )
            
            self.logger.info(f"Telegram alert sent: {message}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Telegram: {e}")
            return False
    
    def send_multi_channel_alert(self, 
                                  subject: str, 
                                  message: str, 
                                  severity: str = 'medium',
                                  channels: List[str] = None):
        """Send alerts across multiple channels"""
        if channels is None:
            channels = ['email', 'sms', 'telegram']
        
        results = {}
        
        # Determine if alert should be sent based on severity
        threshold = self.config.get('alert_thresholds', {}).get(severity, 0)
        
        if 'email' in channels:
            results['email'] = self.send_email_alert(subject, message, severity)
        
        if 'sms' in channels and severity in ['critical', 'high']:
            results['sms'] = self.send_sms_alert(message, severity)
        
        if 'telegram' in channels:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results['telegram'] = loop.run_until_complete(
                self.send_telegram_alert(message, severity)
            )
            loop.close()
        
        return results
    
    def create_attack_report(self, attack_data: Dict) -> str:
        """Create detailed attack report"""
        report = f"""
        Attack Detection Report
        =======================
        
        Attack Type: {attack_data.get('type', 'Unknown')}
        Severity: {attack_data.get('severity', 'Unknown')}
        Confidence: {attack_data.get('confidence', 0):.2%}
        
        Source Information:
        - Source IPs: {', '.join(attack_data.get('source_ips', [])[:10])}
        - Total Sources: {attack_data.get('total_sources', 0)}
        
        Traffic Statistics:
        - Packets Detected: {attack_data.get('packet_count', 0):,}
        - Data Volume: {attack_data.get('data_volume', 0) / 1024 / 1024:.2f} MB
        - Duration: {attack_data.get('duration', 0)} seconds
        - Peak Rate: {attack_data.get('peak_rate', 0):,} packets/sec
        
        Target Information:
        - Target IP: {attack_data.get('target_ip', 'Unknown')}
        - Target Ports: {', '.join(map(str, attack_data.get('target_ports', [])))}
        
        Recommended Actions:
        {chr(10).join(f"- {action}" for action in attack_data.get('recommendations', []))}
        
        Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        return report

# Scheduled alert digest
class AlertDigest:
    def __init__(self, alert_system: AlertSystem):
        self.alert_system = alert_system
        self.daily_stats = {
            'attacks_detected': 0,
            'packets_analyzed': 0,
            'ips_blocked': 0,
            'false_positives': 0
        }
    
    def update_stats(self, stats: Dict):
        """Update daily statistics"""
        for key, value in stats.items():
            if key in self.daily_stats:
                self.daily_stats[key] += value
    
    def send_daily_digest(self):
        """Send daily summary report"""
        subject = "Daily DDoS Detection Summary"
        body = f"""
        Daily Security Report
        =====================
        
        Attacks Detected: {self.daily_stats['attacks_detected']}
        Packets Analyzed: {self.daily_stats['packets_analyzed']:,}
        IPs Blocked: {self.daily_stats['ips_blocked']}
        False Positives: {self.daily_stats['false_positives']}
        
        System Status: Operational
        Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        self.alert_system.send_email_alert(subject, body, 'low')
        
        # Reset stats
        self.daily_stats = {key: 0 for key in self.daily_stats}