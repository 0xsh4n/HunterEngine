"""Tests for the auto-navigator."""

from crawl.auto_navigator import NavigatorConfig, _form_value_for


def test_form_value_for_email():
    """Email fields should return an email address."""
    assert "@" in _form_value_for("user_email", "email")


def test_form_value_for_password():
    """Password fields should return a strong test password."""
    value = _form_value_for("password", "password")
    assert len(value) >= 8


def test_form_value_for_search():
    """Search fields should return a search term."""
    assert _form_value_for("search_query", "text") == "test"


def test_form_value_for_unknown():
    """Unknown fields should return a generic value."""
    value = _form_value_for("xyz_unknown_field", "text")
    assert isinstance(value, str) and len(value) > 0


def test_navigator_config_defaults():
    """NavigatorConfig should have sane defaults."""
    config = NavigatorConfig()
    assert config.headless is False         # Default = visible browser
    assert config.max_pages == 500
    assert config.max_depth == 10
    assert config.form_submit is True
    assert config.click_buttons is True
    assert config.intercept_network is True
