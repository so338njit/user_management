import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.email_service import EmailService
from app.models.user_model import User, UserRole
from app.utils.template_manager import TemplateManager
from datetime import datetime, timezone
from uuid import uuid4
import logging

# Test data
TEST_USER_ID = uuid4()

# Mock user
mock_user = User(
    id=TEST_USER_ID,
    email="test@example.com",
    nickname="testuser",
    first_name="Test",
    last_name="User",
    bio="Test bio",
    role=UserRole.AUTHENTICATED,
    is_professional=False,
    email_verified=True,
    hashed_password="hashed_password",
    created_at=datetime.now(timezone.utc),
    updated_at=datetime.now(timezone.utc),
    last_login_at=datetime.now(timezone.utc)
)

@pytest.fixture
def mock_template_manager():
    template_manager = MagicMock(spec=TemplateManager)
    template_manager.render_template = MagicMock(return_value="Rendered template content")
    return template_manager

@pytest.fixture
def email_service(mock_template_manager):
    # Create an email service with mocked components
    service = EmailService(template_manager=mock_template_manager)
    service.smtp_client = MagicMock()
    service.smtp_client.send_email = MagicMock()
    return service

@pytest.mark.asyncio
async def test_send_verification_email(email_service):
    # Set up mock user with verification token
    user = mock_user
    user.verification_token = "test-verification-token"
    
    # Call the method
    await email_service.send_verification_email(user)
    
    # Check that send_user_email was called with correct parameters
    email_service.template_manager.render_template.assert_called_once()
    email_service.smtp_client.send_email.assert_called_once()
    
    # Check that the first call to send_email had the right email address
    args, kwargs = email_service.smtp_client.send_email.call_args
    assert "test@example.com" in args  # This assumes the email is the third argument

@pytest.mark.asyncio
async def test_send_status_notification(email_service):
    # Set up test cases
    test_cases = [
        {"is_professional": True, "expected_status": "upgraded to professional"},
        {"is_professional": False, "expected_status": "reverted to standard"}
    ]
    
    for case in test_cases:
        # Configure user
        user = mock_user
        user.is_professional = case["is_professional"]
        
        # Call the method under test
        await email_service.send_status_notification(user, case["expected_status"])
        
        # Verify template manager and SMTP client were called correctly
        email_service.template_manager.render_template.assert_called_with(
            'professional_status_update',
            name=user.first_name or user.nickname or "User",
            status_change=case["expected_status"],
            email=user.email,
            is_professional=user.is_professional
        )
        
        # Verify email was sent
        email_service.smtp_client.send_email.assert_called()
        
        # Reset mocks for next test case
        email_service.template_manager.render_template.reset_mock()
        email_service.smtp_client.send_email.reset_mock()

@pytest.mark.asyncio
async def test_send_user_email_professional_status_update(email_service):
    # Test data for a professional status update
    user_data = {
        "name": "Test User",
        "email": "test@example.com",
        "is_professional": True,
        "status_change": "upgraded to professional"
    }
    
    # Call the method
    await email_service.send_user_email(user_data, 'professional_status_update')
    
    # Verify template manager rendered the correct template with data
    email_service.template_manager.render_template.assert_called_with(
        'professional_status_update', **user_data
    )
    
    # Verify the email was sent with correct subject
    email_service.smtp_client.send_email.assert_called_once()
    args, _ = email_service.smtp_client.send_email.call_args
    assert args[0] == "Your Professional Status Update"  # Subject
    assert args[2] == "test@example.com"  # Recipient

@pytest.mark.asyncio
async def test_send_user_email_invalid_type(email_service):
    # Test sending an email with an invalid type
    user_data = {
        "name": "Test User",
        "email": "test@example.com"
    }
    
    # The method should raise a ValueError for invalid email type
    with pytest.raises(ValueError, match="Invalid email type"):
        await email_service.send_user_email(user_data, 'invalid_email_type')

@pytest.mark.asyncio
async def test_send_user_email_smtp_error(email_service):
    # Configure SMTP client to raise an exception
    email_service.smtp_client.send_email.side_effect = Exception("SMTP error")
    
    user_data = {
        "name": "Test User",
        "email": "test@example.com",
        "is_professional": True
    }
    
    # The method should propagate the exception
    with pytest.raises(Exception, match="SMTP error"):
        await email_service.send_user_email(user_data, 'professional_status_update')
    
    # Verify template was still rendered
    email_service.template_manager.render_template.assert_called_once()
    