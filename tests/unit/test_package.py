import re

import domainpilot


def test_version_is_pep440() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(\.dev\d+|rc\d+)?", domainpilot.__version__)
