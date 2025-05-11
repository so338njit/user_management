"""
File: test_combined_features.py

Overview:
This test file validates the interactions between different features of the user management system,
particularly focusing on how profile management and professional status interact with other 
features like account locking, email verification, and user roles.
"""

import pytest
from httpx import AsyncClient
from app.models.user_model import User, UserRole
from datetime import datetime, timezone
from uuid import uuid4

@pytest.mark.asyncio
async def test_unlock_then_update_professional_status(async_client, locked_user, admin_token, db_session):
    """Test unlocking a user and then setting professional status."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # First, unlock the user
    unlock_response = await async_client.post(
        f"/users/{locked_user.id}/unlock",
        headers=headers
    )
    
    assert unlock_response.status_code == 200
    assert "successfully unlocked" in unlock_response.json().get("message", "")
    
    # Verify user is unlocked
    await db_session.refresh(locked_user)
    assert locked_user.is_locked is False
    
    # Then set professional status
    status_update = {
        "is_professional": True
    }
    
    status_response = await async_client.patch(
        f"/users/{locked_user.id}/professional-status",
        json=status_update,
        headers=headers
    )
    
    assert status_response.status_code == 200
    data = status_response.json()
    assert data["is_professional"] is True
    
    # Verify database update
    await db_session.refresh(locked_user)
    assert locked_user.is_professional is True
    assert locked_user.is_locked is False


@pytest.mark.asyncio
async def test_professional_status_persists_after_email_verification(async_client, unverified_user, admin_token, db_session):
    """Test that professional status persists after email verification."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # First, set the user to professional
    status_update = {
        "is_professional": True
    }
    
    await async_client.patch(
        f"/users/{unverified_user.id}/professional-status",
        json=status_update,
        headers=headers
    )
    
    # Verify user is professional but unverified
    await db_session.refresh(unverified_user)
    assert unverified_user.is_professional is True
    assert unverified_user.email_verified is False
    
    # Now verify the email (directly in the database to simulate verification endpoint)
    unverified_user.email_verified = True
    unverified_user.verification_token = None
    await db_session.commit()
    
    # Get the user profile and check status
    from app.dependencies import get_db
    db = await anext(get_db())
    from app.services.user_service import UserService
    verified_user = await UserService.get_by_id(db, unverified_user.id)
    
    assert verified_user.email_verified is True
    assert verified_user.is_professional is True  # Professional status should persist


@pytest.mark.asyncio
async def test_locked_professional_user_can_be_unlocked(async_client, admin_token, db_session):
    """Test that a locked professional user can be unlocked."""
    # Create a locked professional user
    locked_professional = User(
        nickname="lockedpro",
        email="locked_pro@example.com",
        first_name="Locked",
        last_name="Professional",
        hashed_password="$2b$12$fake_hashed_password",
        role=UserRole.AUTHENTICATED,
        is_professional=True,
        email_verified=True,
        is_locked=True,
        failed_login_attempts=5,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        last_login_at=datetime.now(timezone.utc)
    )
    
    db_session.add(locked_professional)
    await db_session.commit()
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Unlock the user
    response = await async_client.post(
        f"/users/{locked_professional.id}/unlock",
        headers=headers
    )
    
    assert response.status_code == 200
    
    # Verify user is unlocked but still professional
    await db_session.refresh(locked_professional)
    assert locked_professional.is_locked is False
    assert locked_professional.is_professional is True


@pytest.mark.asyncio
async def test_change_profile_then_professional_status(async_client, verified_user, admin_token, db_session):
    """Test updating profile and then changing professional status."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # First update profile
    profile_update = {
        "first_name": "Professional",
        "last_name": "Candidate",
        "bio": "Bio before becoming professional"
    }
    
    profile_response = await async_client.patch(
        f"/users/{verified_user.id}/profile",
        json=profile_update,
        headers=headers
    )
    
    assert profile_response.status_code == 200
    
    # Then update professional status
    status_update = {
        "is_professional": True
    }
    
    status_response = await async_client.patch(
        f"/users/{verified_user.id}/professional-status",
        json=status_update,
        headers=headers
    )
    
    assert status_response.status_code == 200
    data = status_response.json()
    assert data["first_name"] == "Professional"
    assert data["last_name"] == "Candidate"
    assert data["bio"] == "Bio before becoming professional"
    assert data["is_professional"] is True
    
    # Verify database update
    await db_session.refresh(verified_user)
    assert verified_user.first_name == "Professional"
    assert verified_user.is_professional is True


@pytest.mark.asyncio
async def test_professional_status_of_user_with_multiple_updates(async_client, verified_user, admin_token, db_session):
    """Test that professional status persists through multiple profile updates."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # First, set to professional
    status_update = {
        "is_professional": True
    }
    
    await async_client.patch(
        f"/users/{verified_user.id}/professional-status",
        json=status_update,
        headers=headers
    )
    
    # Make a series of profile updates
    updates = [
        {"first_name": "Update1"},
        {"last_name": "Update2"},
        {"bio": "Update3"},
        {"github_profile_url": "https://github.com/update4"}
    ]
    
    for update in updates:
        response = await async_client.patch(
            f"/users/{verified_user.id}/profile",
            json=update,
            headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_professional"] is True  # Status should persist in each response
    
    # Verify final database state
    await db_session.refresh(verified_user)
    assert verified_user.first_name == "Update1"
    assert verified_user.last_name == "Update2"
    assert verified_user.bio == "Update3"
    assert verified_user.github_profile_url == "https://github.com/update4"
    assert verified_user.is_professional is True


@pytest.mark.asyncio
async def test_profile_update_with_role_change(async_client, verified_user, admin_token, db_session):
    """Test profile update interacts properly with role changes."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # First make user professional
    status_update = {
        "is_professional": True
    }
    
    await async_client.patch(
        f"/users/{verified_user.id}/professional-status",
        json=status_update,
        headers=headers
    )
    
    # Then update user's role (using the full update endpoint)
    role_update = {
        "role": "MANAGER"
    }
    
    role_response = await async_client.put(
        f"/users/{verified_user.id}",
        json=role_update,
        headers=headers
    )
    
    assert role_response.status_code == 200
    data = role_response.json()
    assert data["role"] == "MANAGER"
    assert data["is_professional"] is True  # Professional status should persist
    
    # Now update profile
    profile_update = {
        "bio": "Manager with professional status"
    }
    
    profile_response = await async_client.patch(
        f"/users/{verified_user.id}/profile",
        json=profile_update,
        headers=headers
    )
    
    assert profile_response.status_code == 200
    data = profile_response.json()
    assert data["role"] == "MANAGER"
    assert data["bio"] == "Manager with professional status"
    assert data["is_professional"] is True
    
    # Verify database
    await db_session.refresh(verified_user)
    assert verified_user.role == UserRole.MANAGER
    assert verified_user.is_professional is True
    assert verified_user.bio == "Manager with professional status"
    