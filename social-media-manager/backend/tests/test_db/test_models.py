"""
Tests for SQLAlchemy database models.

Tests model instantiation, relationships, constraints, and basic CRUD operations.
"""

import pytest
from datetime import datetime, date
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.db.base import Base
from app.db.models import (
    Platform,
    Mention,
    SuggestedReply,
    ScheduledPost,
    ContentTemplate,
    AnalyticsSnapshot,
    Alert,
    ActivityLog,
    SystemConfig,
)


@pytest.fixture(scope="function")
def db_session():
    """
    Create a fresh database session for each test.

    Uses an in-memory SQLite database for fast, isolated testing.
    """
    # Create in-memory SQLite database
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)

    # Create session
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    yield session

    # Cleanup
    session.close()
    Base.metadata.drop_all(engine)


class TestPlatformModel:
    """Tests for the Platform model."""

    def test_create_platform(self, db_session):
        """Test creating a platform instance."""
        platform = Platform(
            name="twitter",
            enabled=True,
            api_credentials={"api_key": "test_key", "api_secret": "test_secret"},
            rate_limits={"requests_per_minute": 100},
        )
        db_session.add(platform)
        db_session.commit()

        assert platform.id is not None
        assert platform.name == "twitter"
        assert platform.enabled is True
        assert platform.created_at is not None
        assert platform.updated_at is not None

    def test_platform_unique_name(self, db_session):
        """Test that platform names must be unique."""
        platform1 = Platform(name="twitter", enabled=True)
        platform2 = Platform(name="twitter", enabled=False)

        db_session.add(platform1)
        db_session.commit()

        db_session.add(platform2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_platform_repr(self, db_session):
        """Test platform string representation."""
        platform = Platform(name="reddit", enabled=True)
        db_session.add(platform)
        db_session.commit()

        repr_str = repr(platform)
        assert "Platform" in repr_str
        assert "reddit" in repr_str
        assert str(platform.id) in repr_str


class TestMentionModel:
    """Tests for the Mention model."""

    def test_create_mention(self, db_session):
        """Test creating a mention instance."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention = Mention(
            platform_id=platform.id,
            external_id="tweet_123456",
            content="Great work on the project!",
            author="user123",
            author_url="https://twitter.com/user123",
            mention_url="https://twitter.com/user123/status/123456",
            mentioned_at=datetime.utcnow(),
            sentiment="positive",
            priority="medium",
            is_processed=False,
            extra_data={"likes": 10, "retweets": 5},
        )
        db_session.add(mention)
        db_session.commit()

        assert mention.id is not None
        assert mention.platform_id == platform.id
        assert mention.sentiment == "positive"
        assert mention.priority == "medium"
        assert mention.is_processed is False

    def test_mention_platform_relationship(self, db_session):
        """Test mention-platform relationship."""
        platform = Platform(name="github", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention = Mention(
            platform_id=platform.id,
            external_id="issue_789",
            content="Found a bug",
            author="developer",
            mention_url="https://github.com/repo/issues/789",
            mentioned_at=datetime.utcnow(),
        )
        db_session.add(mention)
        db_session.commit()

        # Test relationship from mention to platform
        assert mention.platform is not None
        assert mention.platform.name == "github"

        # Test relationship from platform to mentions
        assert len(platform.mentions) == 1
        assert platform.mentions[0].id == mention.id

    def test_mention_unique_external_id(self, db_session):
        """Test that external_id must be unique."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention1 = Mention(
            platform_id=platform.id,
            external_id="tweet_001",
            content="First mention",
            author="user1",
            mention_url="https://twitter.com/status/001",
            mentioned_at=datetime.utcnow(),
        )
        mention2 = Mention(
            platform_id=platform.id,
            external_id="tweet_001",  # Duplicate
            content="Second mention",
            author="user2",
            mention_url="https://twitter.com/status/002",
            mentioned_at=datetime.utcnow(),
        )

        db_session.add(mention1)
        db_session.commit()

        db_session.add(mention2)
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestSuggestedReplyModel:
    """Tests for the SuggestedReply model."""

    def test_create_suggested_reply(self, db_session):
        """Test creating a suggested reply instance."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention = Mention(
            platform_id=platform.id,
            external_id="tweet_999",
            content="How do I use this feature?",
            author="user",
            mention_url="https://twitter.com/status/999",
            mentioned_at=datetime.utcnow(),
        )
        db_session.add(mention)
        db_session.commit()

        reply = SuggestedReply(
            mention_id=mention.id,
            suggested_text="Thanks for asking! Here's how...",
            ai_model="claude-3-opus-20240229",
            confidence_score=0.95,
            rationale="User asking a genuine question about features",
        )
        db_session.add(reply)
        db_session.commit()

        assert reply.id is not None
        assert reply.mention_id == mention.id
        assert reply.confidence_score == 0.95
        assert reply.is_approved is None  # Pending by default

    def test_suggested_reply_mention_relationship(self, db_session):
        """Test suggested reply-mention relationship."""
        platform = Platform(name="reddit", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention = Mention(
            platform_id=platform.id,
            external_id="comment_123",
            content="Need help",
            author="redditor",
            mention_url="https://reddit.com/r/sub/comments/123",
            mentioned_at=datetime.utcnow(),
        )
        db_session.add(mention)
        db_session.commit()

        reply = SuggestedReply(
            mention_id=mention.id,
            suggested_text="Happy to help!",
            ai_model="claude-3-sonnet-20240229",
        )
        db_session.add(reply)
        db_session.commit()

        # Test relationship
        assert reply.mention.id == mention.id
        assert len(mention.suggested_replies) == 1
        assert mention.suggested_replies[0].id == reply.id


class TestScheduledPostModel:
    """Tests for the ScheduledPost model."""

    def test_create_scheduled_post(self, db_session):
        """Test creating a scheduled post instance."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        scheduled_time = datetime.utcnow()
        post = ScheduledPost(
            platform_id=platform.id,
            content="Check out our new feature!",
            media_urls=["https://example.com/image1.png"],
            scheduled_for=scheduled_time,
            created_by="admin",
            status="pending",
        )
        db_session.add(post)
        db_session.commit()

        assert post.id is not None
        assert post.status == "pending"
        assert post.created_by == "admin"
        assert post.approved_by is None
        assert post.posted_at is None

    def test_scheduled_post_platform_relationship(self, db_session):
        """Test scheduled post-platform relationship."""
        platform = Platform(name="github", enabled=True)
        db_session.add(platform)
        db_session.commit()

        post = ScheduledPost(
            platform_id=platform.id,
            content="Release notes for v2.0",
            scheduled_for=datetime.utcnow(),
            created_by="release_bot",
            status="approved",
        )
        db_session.add(post)
        db_session.commit()

        assert post.platform.name == "github"
        assert len(platform.scheduled_posts) == 1


class TestContentTemplateModel:
    """Tests for the ContentTemplate model."""

    def test_create_content_template(self, db_session):
        """Test creating a content template instance."""
        template = ContentTemplate(
            title="How to Install",
            category="faq",
            content="To install, run: pip install dilithion",
            tags=["installation", "getting-started"],
            created_by="admin",
            is_active=True,
        )
        db_session.add(template)
        db_session.commit()

        assert template.id is not None
        assert template.category == "faq"
        assert template.usage_count == 0
        assert template.is_active is True

    def test_content_template_usage_count(self, db_session):
        """Test incrementing usage count."""
        template = ContentTemplate(
            title="Support Template",
            category="support",
            content="We're here to help!",
            created_by="support_team",
        )
        db_session.add(template)
        db_session.commit()

        # Increment usage
        template.usage_count += 1
        db_session.commit()

        assert template.usage_count == 1


class TestAnalyticsSnapshotModel:
    """Tests for the AnalyticsSnapshot model."""

    def test_create_analytics_snapshot(self, db_session):
        """Test creating an analytics snapshot instance."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        snapshot = AnalyticsSnapshot(
            platform_id=platform.id,
            snapshot_date=date.today(),
            followers_count=1000,
            mentions_count=25,
            engagement_rate=3.5,
            sentiment_positive=15,
            sentiment_neutral=8,
            sentiment_negative=2,
            top_posts=[{"id": "post1", "likes": 100}, {"id": "post2", "likes": 80}],
        )
        db_session.add(snapshot)
        db_session.commit()

        assert snapshot.id is not None
        assert snapshot.followers_count == 1000
        assert snapshot.mentions_count == 25
        assert snapshot.engagement_rate == 3.5

    def test_analytics_snapshot_unique_constraint(self, db_session):
        """Test unique constraint on platform_id and snapshot_date."""
        platform = Platform(name="reddit", enabled=True)
        db_session.add(platform)
        db_session.commit()

        today = date.today()
        snapshot1 = AnalyticsSnapshot(
            platform_id=platform.id,
            snapshot_date=today,
            mentions_count=10,
        )
        snapshot2 = AnalyticsSnapshot(
            platform_id=platform.id,
            snapshot_date=today,  # Same date
            mentions_count=20,
        )

        db_session.add(snapshot1)
        db_session.commit()

        db_session.add(snapshot2)
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestAlertModel:
    """Tests for the Alert model."""

    def test_create_alert(self, db_session):
        """Test creating an alert instance."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        alert = Alert(
            alert_type="viral_mention",
            platform_id=platform.id,
            title="Viral Tweet Detected",
            message="Your mention has 1000+ likes",
            severity="info",
            is_read=False,
        )
        db_session.add(alert)
        db_session.commit()

        assert alert.id is not None
        assert alert.alert_type == "viral_mention"
        assert alert.severity == "info"
        assert alert.is_read is False
        assert alert.read_at is None

    def test_alert_relationships(self, db_session):
        """Test alert relationships with platform and mention."""
        platform = Platform(name="github", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention = Mention(
            platform_id=platform.id,
            external_id="issue_urgent",
            content="Critical bug!",
            author="user",
            mention_url="https://github.com/issues/123",
            mentioned_at=datetime.utcnow(),
        )
        db_session.add(mention)
        db_session.commit()

        alert = Alert(
            alert_type="urgent_reply",
            platform_id=platform.id,
            mention_id=mention.id,
            title="Urgent Reply Needed",
            message="Critical issue requires immediate attention",
            severity="critical",
        )
        db_session.add(alert)
        db_session.commit()

        assert alert.platform.name == "github"
        assert alert.mention.external_id == "issue_urgent"


class TestActivityLogModel:
    """Tests for the ActivityLog model."""

    def test_create_activity_log(self, db_session):
        """Test creating an activity log instance."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        log = ActivityLog(
            action_type="post_created",
            user="admin",
            platform_id=platform.id,
            entity_type="scheduled_post",
            entity_id=123,
            details={"content": "New post scheduled", "scheduled_for": "2024-01-01"},
        )
        db_session.add(log)
        db_session.commit()

        assert log.id is not None
        assert log.action_type == "post_created"
        assert log.user == "admin"
        assert log.entity_type == "scheduled_post"
        assert log.entity_id == 123

    def test_activity_log_platform_relationship(self, db_session):
        """Test activity log-platform relationship."""
        platform = Platform(name="reddit", enabled=True)
        db_session.add(platform)
        db_session.commit()

        log = ActivityLog(
            action_type="mention_fetched",
            user="system",
            platform_id=platform.id,
            details={"count": 10},
        )
        db_session.add(log)
        db_session.commit()

        assert log.platform.name == "reddit"


class TestSystemConfigModel:
    """Tests for the SystemConfig model."""

    def test_create_system_config(self, db_session):
        """Test creating a system config instance."""
        config = SystemConfig(
            key="max_mentions_per_fetch",
            value={"limit": 100},
            description="Maximum number of mentions to fetch per API call",
            updated_by="admin",
        )
        db_session.add(config)
        db_session.commit()

        assert config.id is not None
        assert config.key == "max_mentions_per_fetch"
        assert config.value == {"limit": 100}

    def test_system_config_unique_key(self, db_session):
        """Test that config keys must be unique."""
        config1 = SystemConfig(
            key="app_mode",
            value={"mode": "production"},
            updated_by="admin",
        )
        config2 = SystemConfig(
            key="app_mode",  # Duplicate
            value={"mode": "development"},
            updated_by="dev",
        )

        db_session.add(config1)
        db_session.commit()

        db_session.add(config2)
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestModelIntegration:
    """Integration tests for multiple models working together."""

    def test_cascade_delete_platform(self, db_session):
        """Test that deleting a platform cascades to related records."""
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        mention = Mention(
            platform_id=platform.id,
            external_id="tweet_cascade",
            content="Test",
            author="user",
            mention_url="https://twitter.com/status/1",
            mentioned_at=datetime.utcnow(),
        )
        scheduled_post = ScheduledPost(
            platform_id=platform.id,
            content="Test post",
            scheduled_for=datetime.utcnow(),
            created_by="admin",
        )
        db_session.add_all([mention, scheduled_post])
        db_session.commit()

        # Delete platform
        db_session.delete(platform)
        db_session.commit()

        # Verify cascade delete
        assert db_session.query(Mention).filter_by(id=mention.id).first() is None
        assert db_session.query(ScheduledPost).filter_by(id=scheduled_post.id).first() is None

    def test_complete_workflow(self, db_session):
        """Test a complete workflow from mention to reply."""
        # Create platform
        platform = Platform(name="twitter", enabled=True)
        db_session.add(platform)
        db_session.commit()

        # Create mention
        mention = Mention(
            platform_id=platform.id,
            external_id="tweet_workflow",
            content="How does this work?",
            author="curious_user",
            mention_url="https://twitter.com/status/123",
            mentioned_at=datetime.utcnow(),
            priority="high",
        )
        db_session.add(mention)
        db_session.commit()

        # Generate AI reply
        reply = SuggestedReply(
            mention_id=mention.id,
            suggested_text="Great question! Here's how it works...",
            ai_model="claude-3-opus-20240229",
            confidence_score=0.92,
        )
        db_session.add(reply)
        db_session.commit()

        # Create alert for high priority mention
        alert = Alert(
            alert_type="high_priority_mention",
            platform_id=platform.id,
            mention_id=mention.id,
            title="High Priority Mention",
            message="New high priority mention requires attention",
            severity="warning",
        )
        db_session.add(alert)
        db_session.commit()

        # Log the activity
        log = ActivityLog(
            action_type="reply_suggested",
            user="system",
            platform_id=platform.id,
            entity_type="mention",
            entity_id=mention.id,
            details={"confidence": 0.92},
        )
        db_session.add(log)
        db_session.commit()

        # Verify everything is connected
        assert mention.platform.name == "twitter"
        assert len(mention.suggested_replies) == 1
        assert mention.suggested_replies[0].confidence_score == 0.92
        assert len(mention.alerts) == 1
        assert mention.alerts[0].severity == "warning"
