"""Test fixtures."""
from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest
from napalm.base.test.double import BaseTestDouble
from napalm.base.utils import py23_compat
from napalm_gaiaos import gaiaos




@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = gaiaos.GaiaOSDriver
    request.cls.fake_driver = PatchedGaiaDriver
    request.cls.patched_driver = PatchedGaiaDriver
    request.cls.vendor = 'gaiaos'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedGaiaDriver(gaiaos.GaiaOSDriver):
    def __init__(self, hostname, username, password, timeout,  **optional_args):
        super().__init__(hostname, username, password, timeout, optional_args)
        self.patched_attrs = ['device']
        self.device = FakeGaiaDevice()

    def disconnect(self):
        """Disconnect device."""
        pass

    def is_alive(self):
        """Return a flag with the state of the SSH connection."""
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        """Connect device."""
        pass


class FakeGaiaDevice(BaseTestDouble):
    """gaia test double."""


    def send_command(self, command, **kwargs):
        """Send command to device."""
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return py23_compat.text_type(result)

    def send_command_timing(self, command, **kwargs):
        """Send command to device."""
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return py23_compat.text_type(result)
