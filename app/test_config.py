from app.config import config

POSITIVE_INT_KEYS = [
    ("crypto", "nonce_length_bytes"),
    ("crypto", "max_message_bytes"),
    ("crypto", "database_key_length_bytes"),
    ("auth", "access_token_ttl_seconds"),
    ("auth", "refresh_token_ttl_seconds"),
    ("auth", "preauth_token_ttl_seconds"),
    ("auth", "srp_session_ttl_seconds"),
    ("auth", "secret_token_bytes"),
    ("crypto", "totp_key_length_bytes"),
    ("crypto", "symmetric_key_length_bytes"),
    ("auth", "totp_window"),
    ("server", "max_upload_bytes"),
    ("server", "time_for_enforced_http"),
    ("logging", "log_max_bytes"),
    ("logging", "log_backup_count"),
]


def test_config_no_empty_values():
    stack = [("", config)]
    while stack:
        path, obj = stack.pop()
        if isinstance(obj, dict):
            stack.extend(
                ("%s.%s" % (path, k) if path else k, v) for k, v in obj.items()
            )
        elif isinstance(obj, list):
            stack.extend(("%s[%d]" % (path, i), v) for i, v in enumerate(obj))
        else:
            assert obj is not None and obj != "", "config key '%s' has no value" % path


def test_config_positive_int_values():
    for section, key in POSITIVE_INT_KEYS:
        value = config[section][key]
        assert (
            isinstance(value, int) and value > 0
        ), "config.%s.%s must be a positive int, got %r" % (section, key, value)


def test_config_loaded():
    assert isinstance(config, dict) and config
