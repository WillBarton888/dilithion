from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
import os

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )

    # Application
    APP_ENV: str
    APP_NAME: str = "Dilithion Social Media Manager"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Security
    SECRET_KEY: str
    MASTER_ENCRYPTION_KEY: str
    BACKEND_API_KEY: str

    # Database
    DATABASE_URL: str

    # CORS (comma-separated string in .env, converted to list)
    ALLOWED_ORIGINS: str

    # Platform APIs (all required)
    TWITTER_API_KEY: str
    TWITTER_API_SECRET: str
    TWITTER_BEARER_TOKEN: str
    TWITTER_ACCESS_TOKEN: str
    TWITTER_ACCESS_TOKEN_SECRET: str

    REDDIT_CLIENT_ID: str
    REDDIT_CLIENT_SECRET: str
    REDDIT_USER_AGENT: str
    REDDIT_USERNAME: str
    REDDIT_PASSWORD: str

    GITHUB_ACCESS_TOKEN: str
    GITHUB_REPO_NAME: str

    CLAUDE_API_KEY: str
    CLAUDE_MODEL: str = "claude-3-5-sonnet-20241022"

    # Monitoring
    FETCH_INTERVAL_MINUTES: int = 15
    ANALYTICS_SNAPSHOT_HOUR: int = 23
    SCHEDULER_CHECK_INTERVAL_MINUTES: int = 5

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True

    # AI Settings
    MIN_AI_CONFIDENCE: float = 0.7
    AI_MAX_TOKENS: int = 300
    AI_TEMPERATURE: float = 0.7

    # Alerts
    ALERTS_ENABLED: bool = True

    # Data Retention
    MENTION_RETENTION_DAYS: int = 90
    ANALYTICS_RETENTION_DAYS: int = 365
    ACTIVITY_LOG_RETENTION_DAYS: int = 180

    def get_allowed_origins_list(self) -> List[str]:
        """Parse ALLOWED_ORIGINS string into list"""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(',')]

# Global settings instance
settings = Settings()
