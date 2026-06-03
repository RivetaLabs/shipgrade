import pytest

from shipgrade.demo.report import make_demo_report
from shipgrade.models import Report


@pytest.fixture
def demo_report() -> Report:
    return make_demo_report()
