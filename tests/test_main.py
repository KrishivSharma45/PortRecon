"""Tests for the CLI helpers in main.py."""

import pytest

from main import confirm_authorisation, format_duration, parse_args


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(0, "0s"), (42.4, "42s"), (59.6, "1m00s"), (185, "3m05s"), (-3, "0s")],
)
def test_format_duration(seconds, expected):
    assert format_duration(seconds) == expected


def test_parse_args_defaults():
    args = parse_args(["--target", "127.0.0.1"])
    assert args.ports == "1-1000"
    assert len(args.port_list) == 1000
    assert args.threads == 100


def test_parse_args_top100():
    assert len(parse_args(["-t", "127.0.0.1", "-p", "top100"]).port_list) == 100


@pytest.mark.parametrize(
    "argv",
    [
        ["-t", "127.0.0.1", "-p", "99999"],
        ["-t", "127.0.0.1", "--threads", "0"],
        ["-t", "127.0.0.1", "--timeout", "0"],
        ["-p", "80"],  # missing --target
    ],
)
def test_parse_args_rejects_invalid(argv):
    with pytest.raises(SystemExit):
        parse_args(argv)


@pytest.mark.parametrize(("answer", "allowed"), [("yes", True), (" YES ", True), ("y", False), ("no", False), ("", False)])
def test_confirm_authorisation_requires_yes(monkeypatch, answer, allowed):
    monkeypatch.setattr("builtins.input", lambda _prompt: answer)
    assert confirm_authorisation("127.0.0.1") is allowed


def test_confirm_authorisation_eof_is_refusal(monkeypatch):
    def raise_eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert confirm_authorisation("127.0.0.1") is False
