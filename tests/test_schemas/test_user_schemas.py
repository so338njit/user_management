import uuid
import pytest
from pydantic import ValidationError
from datetime import datetime
from app.schemas.user_schemas import (
    UserBase, UserCreate, UserUpdate, UserResponse, 
    UserListResponse, LoginRequest, UserProfileUpdate, 
    ProfessionalStatusUpdate
)
from app.models.user_model import UserRole

# Fixtures for common test data
@pytest.fixture
def user_base_data():
    return {
        "nickname": "john_doe_123",
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "role": "AUTHENTICATED",
        "bio": "I am a software engineer with over 5 years of experience.",
        "profile_picture_url": "https://example.com/profile_pictures/john_doe.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe",
        "is_professional": False
    }

@pytest.fixture
def user_create_data(user_base_data):
    return {**user_base_data, "password": "SecurePassword123!"}

@pytest.fixture
def user_update_data():
    return {
        "email": "john.doe.new@example.com",
        "nickname": "j_doe",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "I specialize in backend development with Python and Node.js.",
        "profile_picture_url": "https://example.com/profile_pictures/john_doe_updated.jpg"
    }

@pytest.fixture
def user_profile_update_data():
    return {
        "first_name": "Updated",
        "last_name": "Name",
        "bio": "This is my updated professional bio",
        "profile_picture_url": "https://example.com/updated-profile.jpg",
        "github_profile_url": "https://github.com/updateduser",
        "linkedin_profile_url": "https://linkedin.com/in/updateduser"
    }

@pytest.fixture
def professional_status_update_data():
    return {
        "is_professional": True
    }

@pytest.fixture
def user_response_data(user_base_data):
    return {
        "id": uuid.uuid4(),
        "nickname": user_base_data["nickname"],
        "first_name": user_base_data["first_name"],
        "last_name": user_base_data["last_name"],
        "role": user_base_data["role"],
        "email": user_base_data["email"],
        "is_professional": user_base_data["is_professional"],
        # "last_login_at": datetime.now(),
        # "created_at": datetime.now(),
        # "updated_at": datetime.now(),
        "links": []
    }

@pytest.fixture
def login_request_data():
    return {"email": "john_doe_123@emai.com", "password": "SecurePassword123!"}

# Tests for UserBase
def test_user_base_valid(user_base_data):
    user = UserBase(**user_base_data)
    assert user.nickname == user_base_data["nickname"]
    assert user.email == user_base_data["email"]
    assert user.is_professional == user_base_data["is_professional"]

# Tests for UserCreate
def test_user_create_valid(user_create_data):
    user = UserCreate(**user_create_data)
    assert user.nickname == user_create_data["nickname"]
    assert user.password == user_create_data["password"]
    assert user.is_professional == user_create_data["is_professional"]

# Tests for UserUpdate
def test_user_update_valid(user_update_data):
    user_update = UserUpdate(**user_update_data)
    assert user_update.email == user_update_data["email"]
    assert user_update.first_name == user_update_data["first_name"]
    # is_professional should be None since it wasn't provided
    assert user_update.is_professional is None

# Tests for UserResponse
def test_user_response_valid(user_response_data):
    user = UserResponse(**user_response_data)
    assert user.id == user_response_data["id"]
    assert user.is_professional == user_response_data["is_professional"]
    # assert user.last_login_at == user_response_data["last_login_at"]

# Tests for LoginRequest
def test_login_request_valid(login_request_data):
    login = LoginRequest(**login_request_data)
    assert login.email == login_request_data["email"]
    assert login.password == login_request_data["password"]

# Parametrized tests for nickname and email validation
@pytest.mark.parametrize("nickname", ["test_user", "test-user", "testuser123", "123test"])
def test_user_base_nickname_valid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    user = UserBase(**user_base_data)
    assert user.nickname == nickname

@pytest.mark.parametrize("nickname", ["test user", "test?user", "", "us"])
def test_user_base_nickname_invalid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Parametrized tests for URL validation
@pytest.mark.parametrize("url", ["http://valid.com/profile.jpg", "https://valid.com/profile.png", None])
def test_user_base_url_valid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    user = UserBase(**user_base_data)
    assert user.profile_picture_url == url

@pytest.mark.parametrize("url", ["ftp://invalid.com/profile.jpg", "http//invalid", "https//invalid"])
def test_user_base_url_invalid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# NEW TESTS FOR PROFESSIONAL STATUS AND PROFILE MANAGEMENT

# Tests for UserUpdate with professional status
def test_user_update_with_professional_status(user_update_data):
    # Add is_professional to update data
    user_update_data["is_professional"] = True
    
    user_update = UserUpdate(**user_update_data)
    assert user_update.email == user_update_data["email"]
    assert user_update.is_professional is True

# Tests for UserProfileUpdate
def test_user_profile_update_valid(user_profile_update_data):
    profile_update = UserProfileUpdate(**user_profile_update_data)
    assert profile_update.first_name == user_profile_update_data["first_name"]
    assert profile_update.last_name == user_profile_update_data["last_name"]
    assert profile_update.bio == user_profile_update_data["bio"]
    assert profile_update.profile_picture_url == user_profile_update_data["profile_picture_url"]
    assert profile_update.github_profile_url == user_profile_update_data["github_profile_url"]
    assert profile_update.linkedin_profile_url == user_profile_update_data["linkedin_profile_url"]

def test_user_profile_update_partial():
    # Test updating only one field
    update_data = {"bio": "Only updating bio"}
    profile_update = UserProfileUpdate(**update_data)
    assert profile_update.bio == "Only updating bio"
    assert profile_update.first_name is None
    assert profile_update.github_profile_url is None

def test_user_profile_update_empty():
    # At least one field must be provided
    with pytest.raises(ValidationError):
        UserProfileUpdate(**{})

# Tests for ProfessionalStatusUpdate
def test_professional_status_update_valid(professional_status_update_data):
    # Test valid professional status updates
    status_update = ProfessionalStatusUpdate(**professional_status_update_data)
    assert status_update.is_professional is True
    
    # Test setting to False
    status_update = ProfessionalStatusUpdate(is_professional=False)
    assert status_update.is_professional is False

def test_professional_status_update_missing():
    # is_professional is required
    with pytest.raises(ValidationError):
        ProfessionalStatusUpdate(**{})

def test_professional_status_update_wrong_type():
    """Test that non-boolean values that can't be converted to boolean raise errors"""
    # For Pydantic v2, simple strings like "True" are automatically converted to boolean
    # So we need to use a value that can't be converted to boolean
    with pytest.raises(ValidationError):
        ProfessionalStatusUpdate(is_professional="NotABoolean")
        
    # Also test with a number that's not 0 or 1 (which would convert to boolean)
    with pytest.raises(ValidationError):
        ProfessionalStatusUpdate(is_professional=42)
        
    # Alternatively, verify that string values are properly converted
    status_update = ProfessionalStatusUpdate(is_professional="true")
    assert status_update.is_professional is True
    
    status_update = ProfessionalStatusUpdate(is_professional="false")
    assert status_update.is_professional is False
    
    status_update = ProfessionalStatusUpdate(is_professional="1")
    assert status_update.is_professional is True
    
    status_update = ProfessionalStatusUpdate(is_professional="0")
    assert status_update.is_professional is False

# Tests for professional status in UserBase
def test_user_base_professional_status_defaults_to_false():
    # When is_professional is not provided, it should default to False
    user_data = {
        "nickname": "default_test",
        "email": "default@example.com",
        "role": "AUTHENTICATED"
    }
    user = UserBase(**user_data)
    assert user.is_professional is False

# Tests for profile URL validations in UserProfileUpdate
@pytest.mark.parametrize("url", ["http://valid.com/profile.jpg", "https://valid.com/profile.png", None])
def test_user_profile_update_url_valid(url):
    """Test that valid URLs (including None) are accepted in profile updates"""
    # If url is None, we need to provide at least one non-None field to satisfy the validator
    if url is None:
        data = {
            "github_profile_url": url,
            "first_name": "Test"  # Adding a non-None field to satisfy the validator
        }
    else:
        data = {"github_profile_url": url}
    
    profile_update = UserProfileUpdate(**data)
    assert profile_update.github_profile_url == url

@pytest.mark.parametrize("url", ["ftp://invalid.com/profile.jpg", "http//invalid", "https//invalid"])
def test_user_profile_update_url_invalid(url):
    data = {"github_profile_url": url}
    with pytest.raises(ValidationError):
        UserProfileUpdate(**data)
