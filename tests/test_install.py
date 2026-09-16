"""Exercise the legacy service handoff with a fake systemctl; never install software."""
from pathlib import Path
import re
import shutil
import subprocess
import unittest


class LegacyServiceHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")
        if not cls.bash:
            git_bash = Path("C:/Program Files/Git/bin/bash.exe")
            cls.bash = str(git_bash) if git_bash.exists() else None
        if not cls.bash:
            raise unittest.SkipTest("requires bash")
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        cls.function = re.search(r"(?ms)^stop_legacy_service\(\) \{\n.*?^\}", source).group(0)

    def handoff(self, command="", active=False, disable_fails=False):
        fixture = r'''
set -euo pipefail
legacy_command_fixture=$1
legacy_active=$2
disable_fails=$3
systemctl() {
  case "$1" in
    show) printf '%s\n' "$legacy_command_fixture" ;;
    disable)
      printf 'CALL: %s\n' "$*"
      if [ "$disable_fails" = yes ]; then return 1; fi
      legacy_active=no ;;
    is-active) [ "$legacy_active" = yes ] ;;
    *) echo 'unexpected systemctl call'; return 99 ;;
  esac
}
'''
        return subprocess.run([self.bash, "-c", fixture + self.function + "\nstop_legacy_service\necho HANDOFF_OK\n",
                               "test", command, "yes" if active else "no", "yes" if disable_fails else "no"],
                              capture_output=True, text=True, encoding="utf-8", timeout=10)

    def test_recognized_old_service_is_stopped_and_disabled(self):
        result = self.handoff("{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /opt/vps-whitelist/whitelist.py daemon ; }", active=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CALL: disable --now vps-whitelist", result.stdout)
        self.assertIn("HANDOFF_OK", result.stdout)

    def test_inactive_old_install_is_disabled_for_future_boots(self):
        result = self.handoff("/usr/bin/python3 /opt/vps-whitelist/whitelist.py daemon")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CALL: disable --now vps-whitelist", result.stdout)

    def test_unrecognized_active_service_is_not_stopped(self):
        result = self.handoff("/opt/another-app/whitelist.py daemon", active=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CALL: disable", result.stdout)
        self.assertNotIn("HANDOFF_OK", result.stdout)

    def test_no_old_service_needs_no_handoff(self):
        result = self.handoff()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("CALL: disable", result.stdout)

    def test_failed_stop_aborts_installation(self):
        result = self.handoff("/usr/bin/python3 /opt/vps-whitelist/whitelist.py daemon", active=True, disable_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("HANDOFF_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
