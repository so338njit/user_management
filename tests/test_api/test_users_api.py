from builtins import str
import pytest
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_user_registration_success(async_client):
    """Test that user registration works with a random email."""
    user_data = {
        "password": "StrongPassword123!",
        "first_name": "Test",
        "last_name": "User",
        "nickname": generate_nickname(),
        "email": "john.doe@example.com",
        "role": "AUTHENTICATED"
    }
    
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 200
    
    # Verify the response contains expected user data
    user_response = response.json()
    assert user_response["first_name"] == "Test"
    assert user_response["last_name"] == "User"
    assert "@" in user_response["email"]  # Verify it's an email format

@pytest.mark.asyncio
async def test_duplicate_email_in_user_service(db_session, verified_user):
    """Test that UserService correctly handles duplicate emails."""
    from app.services.user_service import UserService
    from app.services.email_service import EmailService
    
    # Create a mock email service
    mock_email_service = MagicMock()
    mock_email_service.send_verification_email = AsyncMock()
    
    # Attempt to create a user with the same email
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "first_name": "Another",
        "last_name": "User"
    }
    
    # This should return None because of duplicate email
    result = await UserService.create(db_session, user_data, mock_email_service)
    assert result is None

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # We now expect a 403 Forbidden status code instead of 401
    assert response.status_code == 403
    
    # Check for the specific error message about email verification
    error_detail = response.json().get("detail", "")
    assert "Email address not verified" in error_detail

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

@pytest.mark.asyncio
async def test_unlock_user_account_api(async_client, locked_user, admin_token):
    """Test that an admin can unlock a locked user account via the API."""
    # First confirm the user is indeed locked
    assert locked_user.is_locked is True
    
    # Attempt to unlock the user account as admin
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post(
        f"/users/{locked_user.id}/unlock", 
        headers=headers
    )
    
    # Check response
    assert response.status_code == 200
    assert "successfully unlocked" in response.json().get("message", "")
    
    # Verify the user is now unlocked in the database
    from app.services.user_service import UserService
    from app.dependencies import get_db
    db_session = await anext(get_db())
    
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert refreshed_user.is_locked is False
    assert refreshed_user.failed_login_attempts == 0

@pytest.mark.asyncio
async def test_unlock_user_access_denied(async_client, locked_user, user_token):
    """Test that a regular user cannot unlock a locked account."""
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.post(
        f"/users/{locked_user.id}/unlock", 
        headers=headers
    )
    
    # Regular users should get 403 Forbidden
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_unlock_nonexistent_user(async_client, admin_token):
    """Test attempting to unlock a user that doesn't exist."""
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = await async_client.post(
        f"/users/{non_existent_user_id}/unlock", 
        headers=headers
    )
    
    # Should get 404 Not Found
    assert response.status_code == 404
    assert "User not found" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_unlock_already_unlocked_user(async_client, verified_user, admin_token):
    """Test attempting to unlock a user that is not locked."""
    # Ensure user is not locked
    assert verified_user.is_locked is False
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post(
        f"/users/{verified_user.id}/unlock", 
        headers=headers
    )
    
    # Should get 400 Bad Request
    assert response.status_code == 400
    assert "not locked" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_unlock_user_by_manager(async_client, locked_user, manager_token):
    """Test that a manager can also unlock a locked user account."""
    headers = {"Authorization": f"Bearer {manager_token}"}
    response = await async_client.post(
        f"/users/{locked_user.id}/unlock", 
        headers=headers
    )
    
    # Check response
    assert response.status_code == 200
    assert "successfully unlocked" in response.json().get("message", "")
