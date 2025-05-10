# email_service.py
from builtins import ValueError, dict, str
from settings.config import settings
from app.utils.smtp_connection import SMTPClient
from app.utils.template_manager import TemplateManager
from app.models.user_model import User
import logging

class EmailService:
    def __init__(self, template_manager: TemplateManager):
        # Log SMTP settings for debugging
        logging.info(f"EmailService initializing with SMTP settings:")
        logging.info(f"  Server: {settings.smtp_server}")
        logging.info(f"  Port: {settings.smtp_port} (type: {type(settings.smtp_port).__name__})")
        
        # Always convert port to integer here
        try:
            port = int(settings.smtp_port) if settings.smtp_port else 2525
        except (ValueError, TypeError):
            logging.warning(f"Invalid SMTP port value: {settings.smtp_port}, defaulting to 2525")
            port = 2525
        
        self.smtp_client = SMTPClient(
            server=settings.smtp_server,
            port=port,  # Pass the converted integer port
            username=settings.smtp_username,
            password=settings.smtp_password
        )
        self.template_manager = template_manager

    async def send_user_email(self, user_data: dict, email_type: str):
        subject_map = {
            'email_verification': "Verify Your Account",
            'password_reset': "Password Reset Instructions",
            'account_locked': "Account Locked Notification"
        }

        if email_type not in subject_map:
            raise ValueError("Invalid email type")

        # Log email sending attempt
        logging.info(f"Preparing to send {email_type} email to {user_data.get('email')}")
        
        html_content = self.template_manager.render_template(email_type, **user_data)
        
        # Send email and handle any exceptions at this level for better error reporting
        try:
            self.smtp_client.send_email(subject_map[email_type], html_content, user_data['email'])
            logging.info(f"Successfully initiated sending of {email_type} email to {user_data.get('email')}")
        except Exception as e:
            logging.error(f"Error sending {email_type} email: {str(e)}")
            # Re-raise to maintain original behavior
            raise

    async def send_verification_email(self, user: User):
        logging.info(f"Sending verification email to user {user.id} ({user.email})")
        
        verification_url = f"{settings.server_base_url}verify-email/{user.id}/{user.verification_token}"
        
        # Log details for debugging
        logging.debug(f"Verification URL: {verification_url}")
        
        await self.send_user_email({
            "name": user.first_name,
            "verification_url": verification_url,
            "email": user.email
        }, 'email_verification')