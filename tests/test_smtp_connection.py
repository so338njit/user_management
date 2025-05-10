import pytest
import smtplib
import os
from app.utils.smtp_connection import SMTPClient

def test_smtp_connection():
    """Test that we can connect to Mailtrap"""
    # Get settings from environment
    server = os.environ.get("SMTP_SERVER", "smtp.mailtrap.io")
    port = os.environ.get("SMTP_PORT", "2525")
    username = os.environ.get("SMTP_USERNAME", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    
    # Print settings (without exposing full credentials)
    print(f"Testing SMTP connection to: {server}:{port}")
    print(f"Username available: {bool(username)}")
    print(f"Password available: {bool(password)}")
    
    # Try to connect directly without SMTPClient first
    try:
        print("Testing direct SMTP connection...")
        direct_server = smtplib.SMTP(server, int(port))
        direct_server.starttls()
        if username and password:
            direct_server.login(username, password)
        direct_server.quit()
        print("Direct SMTP connection successful!")
        direct_connection_ok = True
    except Exception as e:
        print(f"Direct SMTP connection failed: {e}")
        direct_connection_ok = False
    
    # Now test through the SMTPClient
    try:
        print("Testing through SMTPClient...")
        client = SMTPClient(server=server, port=port, username=username, password=password)
        # Just send a test email to a fake address (it won't actually be delivered in Mailtrap)
        client.send_email("Test Subject", "<p>Test Content</p>", "test@example.com")
        print("SMTPClient connection successful!")
        client_connection_ok = True
    except Exception as e:
        print(f"SMTPClient connection failed: {e}")
        client_connection_ok = False
    
    # One of these should work for the test to pass
    assert direct_connection_ok or client_connection_ok, "Should be able to connect to SMTP server"
    