import sys


def test_python_runtime_available():
    assert sys.version_info >= (3, 8)
