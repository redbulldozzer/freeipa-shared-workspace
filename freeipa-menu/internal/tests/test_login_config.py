import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

path = Path(__file__).resolve().parents[1] / 'runtime/scripts/configure-login.py'
spec = importlib.util.spec_from_file_location('configure_login', path)
login = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login)


class LoginConfig(unittest.TestCase):
    output = ('   [Seat:*]\n'
              'G  pam-service=shared-workspace-login\n'
              'G  greeter-session=shared-workspace-greeter\n'
              'G  display-setup-script=/usr/local/libexec/shared-workspace-display-setup\n')

    def test_successful_config_can_arrive_on_either_output_stream(self):
        for stdout, stderr in ((self.output, ''), ('', self.output)):
            with self.subTest(stdout=bool(stdout)):
                login.validate_effective_config(SimpleNamespace(stdout=stdout, stderr=stderr))

    def test_real_conflict_or_empty_output_is_rejected(self):
        for output in ('', self.output.replace('greeter-session=shared-workspace-greeter',
                                              'greeter-session=slick-greeter')):
            with self.subTest(output=output), self.assertRaises(SystemExit):
                login.validate_effective_config(SimpleNamespace(stdout='', stderr=output))


if __name__ == '__main__':
    unittest.main()
