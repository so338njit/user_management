from builtins import bool, int, str
from pathlib import Path
from pydantic import Field, AnyUrl, DirectoryPath, validator
from pydantic_settings import BaseSettings
import logging

class Settings(BaseSettings):
    max_login_attempts: int = Field(default=3, description="Background color of QR codes")
    # Server configuration
    server_base_url: AnyUrl = Field(default='http://localhost', description="Base URL of the server")
    server_download_folder: str = Field(default='downloads', description="Folder for storing downloaded files")

    # Security and authentication configuration
    secret_key: str = Field(default="secret-key", description="Secret key for encryption")
    algorithm: str = Field(default="HS256", description="Algorithm used for encryption")
    access_token_expire_minutes: int = Field(default=30, description="Expiration time for access tokens in minutes")
    admin_user: str = Field(default='admin', description="Default admin username")
    admin_password: str = Field(default='secret', description="Default admin password")
    debug: bool = Field(default=False, description="Debug mode outputs errors and sqlalchemy queries")
    jwt_secret_key: str = "a_very_secret_key"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15  # 15 minutes for access token
    refresh_token_expire_minutes: int = 1440  # 24 hours for refresh token
    # Database configuration
    database_url: str = Field(default='postgresql+asyncpg://user:password@postgres/myappdb', description="URL for connecting to the database")

    # Optional: If preferring to construct the SQLAlchemy database URL from components
    postgres_user: str = Field(default='user', description="PostgreSQL username")
    postgres_password: str = Field(default='password', description="PostgreSQL password")
    postgres_server: str = Field(default='localhost', description="PostgreSQL server address")
    postgres_port: str = Field(default='5432', description="PostgreSQL port")
    postgres_db: str = Field(default='myappdb', description="PostgreSQL database name")
    # Discord configuration
    discord_bot_token: str = Field(default='NONE', description="Discord bot token")
    discord_channel_id: int = Field(default=1234567890, description="Default Discord channel ID for the bot to interact", example=1234567890)
    #Open AI Key 
    openai_api_key: str = Field(default='NONE', description="Open AI Api Key")
    send_real_mail: bool = Field(default=False, description="use mock")
    # Email settings for Mailtrap
    smtp_server: str = Field(default='smtp.mailtrap.io', description="SMTP server for sending emails")
    smtp_port: int = Field(default=2525, description="SMTP port for sending emails")
    smtp_username: str = Field(default='your-mailtrap-username', description="Username for SMTP server")
    smtp_password: str = Field(default='your-mailtrap-password', description="Password for SMTP server")

    # Add validator to ensure smtp_port is always an integer
    @validator('smtp_port', pre=True)
    def ensure_int_port(cls, v):
        if v is None or v == '':
            logging.warning("Empty SMTP port provided, using default 2525")
            return 2525
        try:
            port = int(v)
            return port
        except (ValueError, TypeError):
            logging.warning(f"Invalid SMTP port '{v}', using default 2525")
            return 2525

    class Config:
        # If your .env file is not in the root directory, adjust the path accordingly.
        env_file = ".env"
        env_file_encoding = 'utf-8'
        # Add case sensitivity setting
        case_sensitive = False  # Makes env vars case-insensitive

# Log the settings when the module is loaded
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Instantiate settings to be imported in your application
settings = Settings()

# Log key settings (without sensitive info)
logger.info("Settings loaded:")
logger.info(f"SMTP Server: {settings.smtp_server}")
logger.info(f"SMTP Port: {settings.smtp_port} (type: {type(settings.smtp_port).__name__})")
logger.info(f"SMTP Username set: {bool(settings.smtp_username and settings.smtp_username != 'your-mailtrap-username')}")
logger.info(f"SMTP Password set: {bool(settings.smtp_password and settings.smtp_password != 'your-mailtrap-password')}")
logger.info(f"Server Base URL: {settings.server_base_url}")
logger.info(f"Debug mode: {settings.debug}")
