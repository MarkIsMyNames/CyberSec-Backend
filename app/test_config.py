POSITIVE_INT_KEYS = [
    ("crypto", "nonce_length_bytes"),
    ("crypto", "max_message_bytes"),
    ("crypto", "argon2_time_cost"),
    ("crypto", "argon2_memory_cost_kb"),
    ("crypto", "argon2_parallelism"),
    ("crypto", "argon2_hash_len"),
    ("crypto", "database_key_length_bytes"),
    ("auth", "access_token_ttl_minutes"),
    ("auth", "refresh_token_ttl_days"),
    ("auth", "preauth_token_ttl_seconds"),
    ("auth", "totp_window"),
    ("server", "max_upload_bytes"),
    ("logging", "log_max_bytes"),
    ("logging", "log_backup_count"),
]


def test_config_no_empty_values():
    from app.config import get_config
    stack = [("", get_config())]
    while stack:
        path, obj = stack.pop()
        if isinstance(obj, dict):
            stack.extend(("%s.%s" % (path, k) if path else k, v) for k, v in obj.items())
        elif isinstance(obj, list):
            stack.extend(("%s[%d]" % (path, i), v) for i, v in enumerate(obj))
        else:
            assert obj is not None and obj != "", "config key '%s' has no value" % path


def test_config_positive_int_values():
    from app.config import get_config
    cfg = get_config()
    for section, key in POSITIVE_INT_KEYS:
        value = cfg[section][key]
        assert isinstance(value, int) and value > 0, "config.%s.%s must be a positive int, got %r" % (section, key, value)


def test_config_singleton():
    from app.config import get_config
    assert get_config() is get_config()
