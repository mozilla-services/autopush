from autopush.tests import setUp, tearDown


def pytest_configure(config):
    """Called before testing begins"""
    setUp()


def pytest_unconfigure(config):
    """Called after all tests run and warnings displayed"""
    tearDown()
