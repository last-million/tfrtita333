from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    # Database configuration
    db_host: str = Field(..., env="DB_HOST")
    db_user: str = Field(..., env="DB_USER")
    db_password: str = Field(..., env="DB_PASSWORD")
    db_database: str = Field(..., env="DB_DATABASE")
    
    # Twilio credentials
    twilio_account_sid: str = Field(..., env="TWILIO_ACCOUNT_SID")
    twilio_auth_token: str = Field(..., env="TWILIO_AUTH_TOKEN")
    
    # Supabase credentials
    supabase_url: str = Field(..., env="SUPABASE_URL")
    supabase_key: str = Field(..., env="SUPABASE_KEY")
    
    # Google OAuth credentials
    google_client_id: str = Field(..., env="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field(..., env="GOOGLE_CLIENT_SECRET")
    
    # Ultravox API
    ultravox_api_key: str = Field(..., env="ULTRAVOX_API_KEY")
    
    # JWT configuration
    jwt_secret: str = Field(..., env="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    
    # Application settings
    cors_origins: str = Field(..., env="CORS_ORIGINS")
    server_domain: str = Field(..., env="SERVER_DOMAIN")
    debug: bool = Field(True, env="DEBUG")
    
    # LibSQL Database URL (optional)
    database_url: str = Field("file:./data.db", env="DATABASE_URL")
    
    # Encryption settings for credentials
    encryption_salt: str = Field(..., env="ENCRYPTION_SALT")
    secret_key: str = Field(..., env="SECRET_KEY")

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
