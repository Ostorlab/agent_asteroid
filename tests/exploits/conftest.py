"""Expose the same HTTP mock to both Session and public adapter transports."""

from __future__ import annotations

import collections.abc
import typing

import pytest
import requests
import requests_mock as req_mock


@pytest.fixture(scope="function")
def requests_mock(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> collections.abc.Iterator[req_mock.Mocker]:
    """Preserve plugin options/history while intercepting direct adapter sends."""
    case_sensitive = typing.cast(
        bool, request.config.getini("requests_mock_case_sensitive")
    )
    adapter = req_mock.Adapter(case_sensitive=case_sensitive)

    def mocked_adapter(
        session: requests.Session, url: str
    ) -> requests.adapters.BaseAdapter:
        return adapter

    # Install before Mocker starts so its temporary Session.send adapter swap
    # restores this adapter as well, preserving mixed transport tests.
    monkeypatch.setattr(requests.Session, "get_adapter", mocked_adapter)
    with req_mock.Mocker(adapter=adapter, case_sensitive=case_sensitive) as http_mock:
        yield http_mock
