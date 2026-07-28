"""Config loading, precedence, and the validations that prevent footguns."""

from __future__ import annotations

import stat

import pytest
import yaml

from lory_code_security.core.config import Config, load, load_checked
from lory_code_security.core.errors import ConfigError


def write(tmp_path, document):
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump(document))
    return path


def test_missing_file_is_not_an_error(tmp_path):
    cfg = load(tmp_path / "absent.yml")
    assert cfg.base_url.startswith("https://")


def test_environment_beats_the_file(tmp_path, monkeypatch):
    path = write(tmp_path, {"base_url": "https://file.example"})
    monkeypatch.setenv("LORY_BASE_URL", "https://env.example")
    assert load(path).base_url == "https://env.example"


def test_var_token_is_expanded(tmp_path, monkeypatch):
    path = write(tmp_path, {"mcp_token": "${SOME_TOKEN}"})
    monkeypatch.setenv("SOME_TOKEN", "lkmcp_abcdef012345")
    assert load(path).mcp_token == "lkmcp_abcdef012345"


def test_unset_var_token_becomes_none(tmp_path, monkeypatch):
    path = write(tmp_path, {"mcp_token": "${NOT_SET_ANYWHERE}"})
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    assert load(path).mcp_token is None


def test_invalid_yaml_raises_config_error(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text("base_url: [unclosed")
    with pytest.raises(ConfigError):
        load(path)


def test_non_mapping_yaml_raises_config_error(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError):
        load(path)


def test_urls_are_built_from_the_documented_paths():
    cfg = Config(base_url="https://x.example")
    assert cfg.mcp_url() == "https://x.example/ptaas/mcp/"
    assert cfg.chat_url().endswith("/ptaas/ajax/lory-public.php")


def test_retired_keys_are_reported_not_rejected(tmp_path):
    """A config from the session-cookie era must still load."""
    path = write(tmp_path, {
        "base_url": "https://x.example",
        "session_cookie": "abc",
        "surface": "portal",
    })
    cfg = load(path)
    assert set(cfg.retired_keys) >= {"session_cookie", "surface"}
    assert not [e for e in cfg.validate() if "session_cookie" in e]


def test_trailing_slash_does_not_double_up():
    assert Config(base_url="https://x.example/").mcp_url() == "https://x.example/ptaas/mcp/"


def test_plaintext_http_to_a_remote_host_is_rejected(tmp_path):
    cfg = Config(base_url="http://prod.example", repo_root=tmp_path)
    assert any("plaintext" in e for e in cfg.validate())


def test_plaintext_http_to_localhost_is_allowed(tmp_path):
    cfg = Config(base_url="http://localhost:8080", repo_root=tmp_path)
    assert not any("plaintext" in e for e in cfg.validate())


def test_malformed_mcp_token_is_rejected(tmp_path):
    cfg = Config(base_url="https://x.example", mcp_token="not-a-token", repo_root=tmp_path)
    assert any("lkmcp_" in e for e in cfg.validate())


def test_history_above_the_server_cap_is_rejected(tmp_path):
    cfg = Config(base_url="https://x.example", history_limit=100, repo_root=tmp_path)
    assert any("history_limit" in e for e in cfg.validate())


def test_missing_repo_root_is_rejected(tmp_path):
    cfg = Config(base_url="https://x.example", repo_root=tmp_path / "nope")
    assert any("repo_root" in e for e in cfg.validate())


def test_load_checked_raises_on_an_invalid_document(tmp_path):
    path = write(tmp_path, {"base_url": "not-a-url"})
    with pytest.raises(ConfigError):
        load_checked(path)


def test_state_paths_hang_off_state_dir(tmp_path):
    cfg = Config(state_dir=tmp_path / "state")
    assert cfg.findings_cache.parent == tmp_path / "state"
    assert cfg.triage_path.parent == tmp_path / "state"


def test_code_context_is_off_by_default():
    """Source must never leave the machine without an explicit opt-in."""
    assert Config().send_code_context is False


def test_a_quoted_false_does_not_turn_code_sending_on(tmp_path):
    """`bool("false")` is True, which used to silently enable source upload."""
    for word in ("false", "False", "no", "off", "0"):
        path = write(tmp_path, {"send_code_context": word, "verify_tls": word})
        cfg = load(path)
        assert cfg.send_code_context is False, word
        assert cfg.verify_tls is False, word


def test_quoted_truthy_words_still_parse(tmp_path):
    for word in ("true", "YES", "on", "1"):
        assert load(write(tmp_path, {"send_code_context": word})).send_code_context is True, word


def test_an_unparseable_boolean_is_an_error_not_a_guess(tmp_path):
    path = write(tmp_path, {"send_code_context": "maybe"})
    with pytest.raises(ConfigError, match="send_code_context must be true or false"):
        load(path)


def test_written_config_is_not_world_readable(tmp_path):
    from lory_code_security.core.onboarding import Credentials, write_config

    path = write_config(
        tmp_path / "config.yml",
        Credentials(base_url="https://x.example", token="lkmcp_abcdef012345"),
    )
    mode = path.stat().st_mode & 0o777
    assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)
    assert "lkmcp_abcdef012345" in path.read_text()
