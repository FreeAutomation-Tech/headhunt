import sys

import pytest

from src.cli import main


class TestCli:
    def test_no_args_prints_usage(self):
        testargs = ["headhunt"]
        with pytest.raises(SystemExit):
            sys.argv = testargs
            main()

    def test_scan_requires_target(self):
        testargs = ["headhunt", "scan"]
        with pytest.raises(SystemExit):
            sys.argv = testargs
            main()
