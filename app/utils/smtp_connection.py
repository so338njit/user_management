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
        
        # Ensure port is an integer
        try:
            self.port = int(port) if port is not None else 2525
        except (ValueError, TypeError):
            logging.warning(f"Invalid port value: {port}, defaulting to 2525")
            self.port = 2525
            
        self.username = username
        self.password = password
        
        # Log configuration for debugging
        logging.info(f"SMTPClient initialized with server: {server}, port: {self.port}")

    def send_email(self, subject: str, html_content: str, recipient: str):
        try:
            # More detailed logging for debugging
            logging.info(f"Attempting to send email via {self.server}:{self.port} to {recipient}")
            
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.username
            message['To'] = recipient
            message.attach(MIMEText(html_content, 'html'))

            # Create a new connection for each email (don't use context manager)
            logging.debug("Creating SMTP server connection...")
            server = smtplib.SMTP(self.server, self.port)
            
            logging.debug("Enabling TLS...")
            server.starttls()
            
            logging.debug("Logging in...")
            server.login(self.username, self.password)
            
            logging.debug("Sending email...")
            server.sendmail(self.username, recipient, message.as_string())
            
            logging.debug("Closing connection...")
            server.quit()
            
            logging.info(f"Email successfully sent to {recipient}")
            return True
        except Exception as e:
            logging.error(f"Failed to send email: {str(e)}")
            # Print full stack trace for debugging
            import traceback
            logging.error(traceback.format_exc())
            raise