"""
File: test_profile_management.py

Overview:
This test file validates the profile management and professional status functionality.
"""

import pytest
from httpx import AsyncClient
from app.models.user_model import User, UserRole
from datetime import datetime, timezone
from uuid import UUID, uuid4

@pytest.mark.asyncio
async def test_get_current_user_profile(async_client, verified_user, user_token, monkeypatch):
    """Test that a user can retrieve their own profile."""
    # Create a custom override for get_current_user that returns the correct format
    from app.dependencies import get_current_user
    
    async def mock_get_current_user():
        return {
            "id": str(verified_user.id),
            "email": verified_user.email,
            "role": verified_user.role.name
        }
    
    # Override the dependency in the app
    from app.main import app
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Make the request
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get("/profile", headers=headers)
    
    # Clean up the override
    app.dependency_overrides.pop(get_current_user, None)
    
    # Assertions
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(verified_user.id)
    assert data["email"] == verified_user.email
    assert "is_professional" in data
    assert data["role"] == verified_user.role.name


@pytest.mark.asyncio
async def test_update_own_profile(async_client, verified_user, user_token, db_session, monkeypatch):
    """Test that a user can update their own profile."""
    # Create a custom override for get_current_user
    from app.dependencies import get_current_user
    
    async def mock_get_current_user():
        return {
            "id": str(verified_user.id),
            "email": verified_user.email,
            "role": verified_user.role.name
        }
    
    # Override the dependency in the app
    from app.main import app
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Make the request
    headers = {"Authorization": f"Bearer {user_token}"}
    profile_update = {
        "first_name": "Updated",
        "bio": "This is my updated bio"
    }
    
    response = await async_client.patch(
        f"/users/{verified_user.id}/profile",
        json=profile_update,
        headers=headers
    )
    
    # Clean up the override
    app.dependency_overrides.pop(get_current_user, None)
    
    # Assertions
    assert response.status_code == 200
    data = response.json()
    assert data["first_name"] == "Updated"
    assert data["bio"] == "This is my updated bio"
    
    # Verify the changes were saved to the database
    await db_session.refresh(verified_user)
    assert verified_user.first_name == "Updated"
    assert verified_user.bio == "This is my updated bio"


@pytest.mark.asyncio
async def test_update_other_profile_denied(async_client, admin_user, verified_user, user_token, monkeypatch):
    """Test that a regular user cannot update another user's profile."""
    # Create a custom override for get_current_user
    from app.dependencies import get_current_user
    
    async def mock_get_current_user():
        return {
            "id": str(verified_user.id),
            "email": verified_user.email,
            "role": verified_user.role.name
        }
    
    # Override the dependency in the app
    from app.main import app
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Make the request
    headers = {"Authorization": f"Bearer {user_token}"}
    profile_update = {
        "first_name": "Should Fail",
        "bio": "This update should be rejected"
    }
    
    response = await async_client.patch(
        f"/users/{admin_user.id}/profile",
        json=profile_update,
        headers=headers
    )
    
    # Clean up the override
    app.dependency_overrides.pop(get_current_user, None)
    
    # Assertions
    assert response.status_code == 403
    assert "You can only update your own profile" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_admin_update_other_profile(async_client, verified_user, admin_user, admin_token, db_session, monkeypatch):
    """Test that an admin can update another user's profile."""
    # Create a custom override for get_current_user
    from app.dependencies import get_current_user
    
    async def mock_get_current_user():
        return {
            "id": str(admin_user.id),
            "email": admin_user.email,
            "role": admin_user.role.name
        }
    
    # Override the dependency in the app
    from app.main import app
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Make the request
    headers = {"Authorization": f"Bearer {admin_token}"}
    profile_update = {
        "first_name": "Admin Updated",
        "bio": "This user was updated by an admin"
    }
    
    response = await async_client.patch(
        f"/users/{verified_user.id}/profile",
        json=profile_update,
        headers=headers
    )
    
    # Clean up the override
    app.dependency_overrides.pop(get_current_user, None)
    
    # Assertions
    assert response.status_code == 200
    data = response.json()
    assert data["first_name"] == "Admin Updated"
    assert data["bio"] == "This user was updated by an admin"
    
    # Verify the changes were saved to the database
    await db_session.refresh(verified_user)
    assert verified_user.first_name == "Admin Updated"
    assert verified_user.bio == "This user was updated by an admin"


@pytest.mark.asyncio
async def test_update_professional_status_as_admin(async_client, verified_user, admin_user, admin_token, db_session, monkeypatch):
    """Test that an admin can update a user's professional status."""
    # Create a custom override for require_role
    from app.dependencies import require_role
    
    def mock_require_role(roles):
        async def _require_role(token: str = None):
            return {
                "id": str(admin_user.id),
                "email": admin_user.email,
                "role": admin_user.role.name
            }
        return _require_role
    
    # Override the dependency in the app
    from app.main import app
    app.dependency_overrides[require_role] = mock_require_role
    
    # Make the request
    headers = {"Authorization": f"Bearer {admin_token}"}
    status_update = {
        "is_professional": True
    }
    
    response = await async_client.patch(
        f"/users/{verified_user.id}/professional-status",
        json=status_update,
        headers=headers
    )
    
    # Clean up the override
    app.dependency_overrides.pop(require_role, None)
    
    # Assertions
    assert response.status_code == 200
    data = response.json()
    assert data["is_professional"] is True
    
    # Verify the change was saved to the database
    await db_session.refresh(verified_user)
    assert verified_user.is_professional is True
    assert verified_user.professional_status_updated_at is not None

