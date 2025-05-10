# smtp_client.py
from builtins import Exception, int, str
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from settings.config import settings
import logging

class SMTPClient:
    def __init__(self, server: str, port: int, username: str, password: str):
        self.server = server
        self.port = int(port) if isinstance(port, str) else port
        self.username = username
        self.password = password

    def send_email(self, subject: str, html_content: str, recipient: str):
        try:
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.username
            message['To'] = recipient
            message.attach(MIMEText(html_content, 'html'))

            # Create the SMTP connection and explicitly connect
            server = smtplib.SMTP(self.server, self.port)
            server.connect(self.server, self.port)  # Explicitly connect to the server
            server.starttls()  # Use TLS
            server.login(self.username, self.password)
            server.sendmail(self.username, recipient, message.as_string())
            server.quit()  # Close the connection
            
            logging.info(f"Email sent to {recipient}")
            return True
        except Exception as e:
            logging.error(f"Failed to send email: {str(e)}")
            raise
