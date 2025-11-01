"""
SQLAlchemy database models for Social Media Manager.

This module defines all database models including platforms, mentions,
replies, scheduled posts, analytics, and more.
"""

from datetime import datetime, date
from typing import Optional
from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    Text,
    Float,
    DateTime,
    Date,
    ForeignKey,
    JSON,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base


class Platform(Base):
    """
    Social media platform configuration (Twitter, Reddit, GitHub).

    Stores platform-specific settings, API credentials, and rate limits.
    """

    __tablename__ = "platforms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False)
    api_credentials = Column(JSON, nullable=True)  # Encrypted credentials
    rate_limits = Column(JSON, nullable=True)  # Platform-specific rate limit config
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    mentions = relationship("Mention", back_populates="platform", cascade="all, delete-orphan")
    scheduled_posts = relationship(
        "ScheduledPost", back_populates="platform", cascade="all, delete-orphan"
    )
    analytics_snapshots = relationship(
        "AnalyticsSnapshot", back_populates="platform", cascade="all, delete-orphan"
    )
    alerts = relationship("Alert", back_populates="platform")
    activity_logs = relationship("ActivityLog", back_populates="platform")

    def __repr__(self) -> str:
        return f"<Platform(id={self.id}, name='{self.name}', enabled={self.enabled})>"


class Mention(Base):
    """
    Social media mentions from various platforms.

    Tracks mentions that require response or monitoring across all platforms.
    """

    __tablename__ = "mentions"

    id = Column(Integer, primary_key=True, index=True)
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=False)
    external_id = Column(String(255), unique=True, nullable=False, index=True)
    content = Column(Text, nullable=False)
    author = Column(String(255), nullable=False)
    author_url = Column(String(512), nullable=True)
    mention_url = Column(String(512), nullable=False)
    mentioned_at = Column(DateTime(timezone=True), nullable=False)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    sentiment = Column(
        String(20),
        nullable=False,
        default="neutral",
    )  # 'positive', 'neutral', 'negative'
    priority = Column(
        String(20), nullable=False, default="medium"
    )  # 'low', 'medium', 'high', 'urgent'
    is_processed = Column(Boolean, default=False, nullable=False, index=True)
    extra_data = Column(JSON, nullable=True)  # Additional platform-specific data

    # Relationships
    platform = relationship("Platform", back_populates="mentions")
    suggested_replies = relationship(
        "SuggestedReply", back_populates="mention", cascade="all, delete-orphan"
    )
    alerts = relationship("Alert", back_populates="mention")

    # Indexes for performance
    __table_args__ = (
        Index("ix_mentions_platform_processed", "platform_id", "is_processed"),
        Index("ix_mentions_priority_mentioned_at", "priority", "mentioned_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Mention(id={self.id}, platform_id={self.platform_id}, "
            f"author='{self.author}', priority='{self.priority}', "
            f"is_processed={self.is_processed})>"
        )


class SuggestedReply(Base):
    """
    AI-generated reply suggestions for mentions.

    Stores Claude-generated replies with confidence scores and approval status.
    """

    __tablename__ = "suggested_replies"

    id = Column(Integer, primary_key=True, index=True)
    mention_id = Column(Integer, ForeignKey("mentions.id"), nullable=False)
    suggested_text = Column(Text, nullable=False)
    ai_model = Column(String(100), nullable=False)  # e.g., 'claude-3-opus-20240229'
    confidence_score = Column(Float, nullable=True)  # 0.0 to 1.0
    rationale = Column(Text, nullable=True)  # AI's reasoning for the suggestion
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_approved = Column(Boolean, nullable=True)  # None=pending, True=approved, False=rejected
    approved_by = Column(String(255), nullable=True)  # User who approved/rejected
    approved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    mention = relationship("Mention", back_populates="suggested_replies")

    def __repr__(self) -> str:
        return (
            f"<SuggestedReply(id={self.id}, mention_id={self.mention_id}, "
            f"model='{self.ai_model}', is_approved={self.is_approved})>"
        )


class ScheduledPost(Base):
    """
    Scheduled social media posts.

    Manages post scheduling, approval workflow, and posting status.
    """

    __tablename__ = "scheduled_posts"

    id = Column(Integer, primary_key=True, index=True)
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=False)
    content = Column(Text, nullable=False)
    media_urls = Column(JSON, nullable=True)  # Array of media URLs
    scheduled_for = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_by = Column(String(255), nullable=False)
    status = Column(
        String(20), nullable=False, default="pending", index=True
    )  # 'pending', 'approved', 'posted', 'failed', 'cancelled'
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    posted_at = Column(DateTime(timezone=True), nullable=True)
    external_post_id = Column(String(255), nullable=True)  # Platform's post ID after posting
    error_message = Column(Text, nullable=True)  # Error details if status='failed'
    extra_data = Column(JSON, nullable=True)  # Additional configuration

    # Relationships
    platform = relationship("Platform", back_populates="scheduled_posts")

    # Indexes for performance
    __table_args__ = (Index("ix_scheduled_posts_status_scheduled_for", "status", "scheduled_for"),)

    def __repr__(self) -> str:
        return (
            f"<ScheduledPost(id={self.id}, platform_id={self.platform_id}, "
            f"status='{self.status}', scheduled_for='{self.scheduled_for}')>"
        )


class ContentTemplate(Base):
    """
    Reusable content templates for FAQs and common responses.

    Provides a library of pre-written content for quick responses.
    """

    __tablename__ = "content_templates"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False, index=True)
    category = Column(
        String(50), nullable=False, index=True
    )  # 'faq', 'announcement', 'support', 'marketing'
    content = Column(Text, nullable=False)
    tags = Column(JSON, nullable=True)  # Array of tags for searching
    usage_count = Column(Integer, default=0, nullable=False)
    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    def __repr__(self) -> str:
        return (
            f"<ContentTemplate(id={self.id}, title='{self.title}', "
            f"category='{self.category}', usage_count={self.usage_count})>"
        )


class AnalyticsSnapshot(Base):
    """
    Daily analytics snapshots for each platform.

    Captures daily metrics including followers, mentions, engagement, and sentiment.
    """

    __tablename__ = "analytics_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=False)
    snapshot_date = Column(Date, nullable=False)
    followers_count = Column(Integer, nullable=True)
    mentions_count = Column(Integer, default=0, nullable=False)
    engagement_rate = Column(Float, nullable=True)  # Percentage
    sentiment_positive = Column(Integer, default=0, nullable=False)
    sentiment_neutral = Column(Integer, default=0, nullable=False)
    sentiment_negative = Column(Integer, default=0, nullable=False)
    top_posts = Column(JSON, nullable=True)  # Array of top performing posts
    extra_data = Column(JSON, nullable=True)  # Additional platform-specific metrics

    # Relationships
    platform = relationship("Platform", back_populates="analytics_snapshots")

    # Indexes and constraints
    __table_args__ = (
        Index("ix_analytics_platform_date", "platform_id", "snapshot_date"),
        UniqueConstraint("platform_id", "snapshot_date", name="uq_platform_snapshot_date"),
    )

    def __repr__(self) -> str:
        return (
            f"<AnalyticsSnapshot(id={self.id}, platform_id={self.platform_id}, "
            f"date='{self.snapshot_date}', mentions={self.mentions_count})>"
        )


class Alert(Base):
    """
    Smart alerts and notifications.

    Notifies users about important events like viral mentions or urgent issues.
    """

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50), nullable=False, index=True)  # e.g., 'viral_mention', 'urgent_reply', 'rate_limit'
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=True)
    mention_id = Column(Integer, ForeignKey("mentions.id"), nullable=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(
        String(20), nullable=False, default="info", index=True
    )  # 'info', 'warning', 'critical'
    is_read = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    platform = relationship("Platform", back_populates="alerts")
    mention = relationship("Mention", back_populates="alerts")

    # Indexes for performance
    __table_args__ = (Index("ix_alerts_is_read_created_at", "is_read", "created_at"),)

    def __repr__(self) -> str:
        return (
            f"<Alert(id={self.id}, type='{self.alert_type}', "
            f"severity='{self.severity}', is_read={self.is_read})>"
        )


class ActivityLog(Base):
    """
    Audit trail for all system activities.

    Tracks user actions, API calls, and system events for compliance and debugging.
    """

    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    action_type = Column(String(100), nullable=False, index=True)  # e.g., 'post_created', 'reply_sent', 'mention_fetched'
    user = Column(String(255), nullable=False, index=True)  # User who performed the action
    platform_id = Column(Integer, ForeignKey("platforms.id"), nullable=True)
    entity_type = Column(String(50), nullable=True)  # e.g., 'mention', 'scheduled_post', 'alert'
    entity_id = Column(Integer, nullable=True)  # ID of the affected entity
    details = Column(JSON, nullable=True)  # Additional context about the action
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Relationships
    platform = relationship("Platform", back_populates="activity_logs")

    # Indexes for performance
    __table_args__ = (Index("ix_activity_logs_entity", "entity_type", "entity_id"),)

    def __repr__(self) -> str:
        return (
            f"<ActivityLog(id={self.id}, action='{self.action_type}', "
            f"user='{self.user}', created_at='{self.created_at}')>"
        )


class SystemConfig(Base):
    """
    Application-wide configuration settings.

    Stores system configuration as key-value pairs with version control.
    """

    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(JSON, nullable=False)  # Flexible JSON storage for any config type
    description = Column(Text, nullable=True)
    updated_by = Column(String(255), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<SystemConfig(id={self.id}, key='{self.key}', updated_by='{self.updated_by}')>"
