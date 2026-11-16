"""Fixtures every test shares."""
from __future__ import annotations

import pytest

from project_discovery.catalog.hosting import configure_provider_map


@pytest.fixture(autouse=True)
def _no_leftover_provider_map():
    """A provider map one test configures (pdt scan --provider-map runs in-process) never
    classifies the hosts of the next."""
    yield
    configure_provider_map(None)
