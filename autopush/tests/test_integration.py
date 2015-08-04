import os
import subprocess
from unittest.case import SkipTest

from twisted.trial import unittest


moto_process = None


def setUp():
    if "SKIP_INTEGRATION" in os.environ:
        raise SkipTest("Skipping integration tests")
    global moto_process
    cmd = "moto_server dynamodb2 -p 5000"
    moto_process = subprocess.Popen(cmd)


def tearDown():
    global moto_process
    moto_process.terminate()


class TestIntegration(unittest.TestCase):
    def test_basic(self):
        pass
