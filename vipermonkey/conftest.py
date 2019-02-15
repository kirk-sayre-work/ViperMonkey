import pytest

def pytest_addoption(parser):
    parser.addoption("--path", action="store")

@pytest.fixture(scope='session')
def path(request):
    path_value = request.config.option.path
    if path_value is None:
        pytest.skip("path to maldocs not specified")
    return path_value
