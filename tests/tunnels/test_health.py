import shlex

import pytest
from app.monitoring.health import HealthProbe, build_remote_curl_command, validate_health_url


@pytest.mark.parametrize("url", ["file:///etc/passwd", "https://user:secret@example.com/", "https://example.com/\nwhoami"])
def test_health_url_rejects_unsafe_inputs(url):
    with pytest.raises(ValueError):
        validate_health_url(url)


def test_curl_template_keeps_url_one_argument_and_disables_rc():
    url = "https://example.com/path?x=';touch%20nope"
    args = shlex.split(build_remote_curl_command(url, 25000))
    assert args[:2] == ["curl", "-q"]
    assert args[-1] == url
    assert args[args.index("--noproxy") + 1] == ""
    assert args[args.index("--proto") + 1] == "=http,https"
    assert "-k" not in args


def test_curl_metrics_preserve_missing_tls_and_failures():
    http = HealthProbe.from_curl("200 0.120 0.000 0.010")
    assert http.total_ms == 120
    assert http.tls_completed_ms is None
    tls = HealthProbe.from_curl("204 0.200 0.150 0.010")
    assert tls.tls_completed_ms == 150
    assert tls.tls_handshake_ms == 140
    assert HealthProbe.from_curl("200 nan 0 0").error_code == "PROBE_PARSE_ERROR"
    assert not HealthProbe.from_curl("200 .2 .1 .01", transport_exit=60).transport_ok
    assert HealthProbe.from_curl("", transport_exit=127).error_code == "PROBE_UNAVAILABLE"


def test_http_connect_status_is_real_and_absent_for_plain_http():
    assert HealthProbe.from_curl("200 .2 .15 .01 200").http_connect_status == 200
    assert HealthProbe.from_curl("200 .2 0 .01 0").http_connect_status is None
    assert HealthProbe.from_curl("200 .2 .15 .01 999").error_code == "PROBE_PARSE_ERROR"
