import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

class NotificationSystem:
    def __init__(self, smtp_server="smtp.gmail.com", smtp_port=587, sender_email="", sender_password="", admin_email=""):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.admin_email = admin_email
        self.enabled = False
        
        if self.sender_email and self.sender_password and self.admin_email:
            self.enabled = True

    def send_alert(self, subject, message):
        """Send email alert in a background thread"""
        if not self.enabled:
            return
            
        t = threading.Thread(target=self._send_email_thread, args=(subject, message))
        t.start()

    def _send_email_thread(self, subject, message):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.admin_email
            msg['Subject'] = f"IDS ALERT: {subject}"

            msg.attach(MIMEText(message, 'plain'))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            text = msg.as_string()
            server.sendmail(self.sender_email, self.admin_email, text)
            server.quit()
            print(f"📧 Email notification sent to {self.admin_email}")
        except Exception as e:
            print(f"❌ Failed to send email: {e}")

    def update_config(self, sender_email, sender_password, admin_email):
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.admin_email = admin_email
        self.enabled = bool(sender_email and sender_password and admin_email)
