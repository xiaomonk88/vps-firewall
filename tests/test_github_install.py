"""Release validation without network or host installation."""
import io
import json
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

import github_install as installer


def package(version="1.0.0", missing=None, extra=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name in installer.FILES:
            if name != missing:
                archive.writestr("vps-firewall-1.0.0/" + name,
                                 version if name == "VERSION" else "test content")
        if extra:
            archive.writestr(*extra)
    return stream.getvalue()


class ReleaseValidation(unittest.TestCase):
    def test_valid_archive_only_extracts_expected_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            installer.unpack_release(package(extra=("vps-firewall-1.0.0/../../outside", "bad")),
                                     destination, "v1.0.0")
            self.assertEqual({path.name for path in destination.iterdir()}, set(installer.FILES))
            self.assertEqual((destination / "VERSION").read_text(), "1.0.0")

    def test_version_mismatch_does_not_write_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "VERSION"):
                installer.unpack_release(package("9.0.0"), Path(temporary), "v1.0.0")
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_incomplete_release_does_not_write_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "VERSION"):
                installer.unpack_release(package(missing="VERSION"), Path(temporary), "v1.0.0")
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_rejects_ambiguous_archive_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                installer.unpack_release(package(extra=("another/install.sh", "bad")),
                                         Path(temporary), "v1.0.0")

    def test_rejects_unexpected_repositories_and_tags(self):
        for repo in ("https://github.com/a/b", "a/b/../c", "a/b?x=y", "a b/c", "a/..", None):
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                installer.validate_repo(repo)
        for tag in ("main", "v1.0.0;id", "v1.0.0-beta", "../main", None):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                installer.validate_tag(tag)
        self.assertEqual(installer.validate_repo("xiaomonk88/vps-firewall"), "xiaomonk88/vps-firewall")
        self.assertEqual(installer.validate_tag("v1.2.3"), "v1.2.3")

    def test_download_limit(self):
        response = io.BytesIO(b"123456")
        with patch.object(installer, "MAX_DOWNLOAD", 5), \
                patch.object(installer.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(ValueError, "大小"):
                installer.download("https://example.com/release.zip")


class UpdateFlow(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.source = self.directory / "source.json"
        self.stack.enter_context(patch.object(installer, "INSTALL_DIR", self.directory))
        self.stack.enter_context(patch.object(installer, "SOURCE_PATH", self.source))
        self.stack.enter_context(patch.object(installer, "LOCK_PATH", self.directory / "update.lock"))
        self.stack.enter_context(patch.object(installer.sys, "platform", "linux"))
        self.stack.enter_context(patch.object(installer.os, "geteuid", return_value=0, create=True))
        fake_lock = SimpleNamespace(flock=Mock(), LOCK_EX=2, LOCK_NB=4)
        self.stack.enter_context(patch.dict("sys.modules", {"fcntl": fake_lock}))
        self.backup = self.stack.enter_context(patch.object(installer, "backup_installation"))
        self.run = self.stack.enter_context(patch.object(installer.subprocess, "run"))
        self.download = self.stack.enter_context(patch.object(installer, "download"))
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.stack.enter_context(redirect_stderr(io.StringIO()))

    def test_latest_release_records_source_only_after_install(self):
        self.download.side_effect = [b'{"tag_name":"v1.0.0"}', package()]
        self.assertEqual(installer.main(["--rescue", "192.0.2.1"]), 0)
        self.assertEqual(json.loads(self.source.read_text()),
                         {"repo": installer.DEFAULT_REPO, "tag": "v1.0.0"})
        self.assertEqual(self.run.call_args.args[0][-1], "192.0.2.1")
        self.backup.assert_called_once()

    def test_failed_install_keeps_previous_source(self):
        original = {"repo": installer.DEFAULT_REPO, "tag": "v0.9.0"}
        self.source.write_text(json.dumps(original))
        self.download.return_value = package()
        self.run.side_effect = [None, None, subprocess.CalledProcessError(1, "bash")]
        self.assertEqual(installer.main(["--tag", "v1.0.0"]), 1)
        self.assertEqual(json.loads(self.source.read_text()), original)

    def test_invalid_release_never_runs_installer_or_backup(self):
        self.download.return_value = package("9.0.0")
        self.assertEqual(installer.main(["--tag", "v1.0.0"]), 1)
        self.run.assert_not_called()
        self.backup.assert_not_called()
        self.assertFalse(self.source.exists())

    def test_current_release_does_not_reinstall(self):
        self.source.write_text(json.dumps({"repo": installer.DEFAULT_REPO, "tag": "v1.0.0"}))
        (self.directory / "VERSION").write_text("1.0.0\n")
        self.assertEqual(installer.main(["--tag", "v1.0.0"]), 0)
        self.download.assert_not_called()
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
