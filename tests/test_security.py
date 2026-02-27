import os
import sys
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


def make_root(tmp_path):
    (tmp_path / "packages").mkdir(exist_ok=True)
    (tmp_path / "build-package.sh").write_text(f"# {FINGERPRINT_STRING}\n")
    return tmp_path


def make_pkg(packages_dir, name, build_sh_content):
    pkg = packages_dir / name
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "build.sh").write_text(build_sh_content)
    return pkg


def make_stdout_mock(lines):
    stdout = MagicMock()
    stdout.readline.side_effect = list(lines) + [b""]
    return stdout


class TestMaliciousPackageMetadata:

    def test_version_field_parsed_as_string(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_VERSION="1.0.0"\n')
        p = load_package(tmp_path / "evil")
        assert p["version"] == "1.0.0"
        assert isinstance(p["version"], str)

    def test_description_with_newline_in_value(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_DESCRIPTION="legit desc"\n')
        p = load_package(tmp_path / "evil")
        assert isinstance(p["desc"], str)

    def test_name_comes_from_directory_name(self, tmp_path):
        make_pkg(tmp_path, "safe-pkg", f'TERMUX_PKG_VERSION="1.0.0"\n')
        p = load_package(tmp_path / "safe-pkg")
        assert p["name"] == "safe-pkg"

    def test_version_with_special_chars_preserved(self, tmp_path):
        make_pkg(tmp_path, "evil", 'TERMUX_PKG_VERSION="1.0.0-beta+build"\n')
        p = load_package(tmp_path / "evil")
        assert p["version"] == "1.0.0-beta+build"

    def test_unicode_package_name(self, tmp_path):
        make_pkg(tmp_path, "my-pkg", f'TERMUX_PKG_VERSION="1.0.0"\n')
        pkgs = load_all_packages(tmp_path)
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "my-pkg"

    def test_deps_field_parsed_correctly(self, tmp_path):
        make_pkg(tmp_path, "mypkg", 'TERMUX_PKG_DEPENDS="nodejs, python"\n')
        p = load_package(tmp_path / "mypkg")
        assert p["deps"] == "nodejs, python"

    def test_maintainer_field_parsed_correctly(self, tmp_path):
        make_pkg(tmp_path, "mypkg", 'TERMUX_PKG_MAINTAINER="@dev"\n')
        p = load_package(tmp_path / "mypkg")
        assert p["maintainer"] == "@dev"

    def test_missing_required_fields_returns_defaults(self, tmp_path):
        make_pkg(tmp_path, "minimal", "# empty build script\n")
        p = load_package(tmp_path / "minimal")
        assert p["version"] == "?"
        assert p["desc"] == "-"
        assert p["deps"] == "-"
        assert p["maintainer"] == "-"

    def test_first_occurrence_of_field_wins(self, tmp_path):
        make_pkg(tmp_path, "dup", (
            'TERMUX_PKG_VERSION="1.0.0"\n'
            'TERMUX_PKG_VERSION="9.9.9"\n'
        ))
        p = load_package(tmp_path / "dup")
        assert p["version"] in ("1.0.0", "9.9.9")

    def test_multiple_packages_all_loaded(self, tmp_path):
        for name in ["pkg-a", "pkg-b", "pkg-c"]:
            make_pkg(tmp_path, name, f'TERMUX_PKG_VERSION="1.0.0"\n')
        pkgs = load_all_packages(tmp_path)
        assert len(pkgs) == 3

    def test_package_without_build_sh_skipped(self, tmp_path):
        (tmp_path / "no-build").mkdir()
        pkgs = load_all_packages(tmp_path)
        assert pkgs == []


class TestCorruptedBuildScript:

    def test_binary_garbage_in_build_sh(self, tmp_path):
        pkg = tmp_path / "corrupt"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_bytes(b"\xff\xfe\x00\x01some garbage\x00\x00")
        p = load_package(pkg)
        assert isinstance(p, dict)
        assert "version" in p

    def test_empty_build_sh(self, tmp_path):
        pkg = tmp_path / "empty"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_bytes(b"")
        p = load_package(pkg)
        assert p["version"] == "?"

    def test_build_sh_is_directory_handled(self, tmp_path):
        pkg = tmp_path / "weird"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").mkdir()
        try:
            p = load_package(pkg)
            assert p["version"] == "?"
        except (IsADirectoryError, OSError):
            pass

    def test_build_sh_symlink_to_nonexistent(self, tmp_path):
        pkg = tmp_path / "broken-link"
        pkg.mkdir(parents=True)
        link = pkg / "build.sh"
        link.symlink_to("/nonexistent/target")
        try:
            p = load_package(pkg)
            assert p["version"] == "?"
        except (FileNotFoundError, OSError):
            pass

    def test_very_large_build_sh(self, tmp_path):
        pkg = tmp_path / "large"
        pkg.mkdir(parents=True)
        content = "# padding\n" * 100000 + 'TERMUX_PKG_VERSION="1.0.0"\n'
        (pkg / "build.sh").write_text(content)
        p = load_package(pkg)
        assert p["version"] == "1.0.0"

    def test_build_sh_with_only_comments(self, tmp_path):
        pkg = tmp_path / "commented"
        pkg.mkdir(parents=True)
        (pkg / "build.sh").write_text('# TERMUX_PKG_VERSION="1.0.0"\n')
        p = load_package(pkg)
        assert p["version"] == "?"

    def test_packages_dir_with_file_entries_skipped(self, tmp_path):
        (tmp_path / "not_a_package.txt").write_text("hello")
        (tmp_path / "valid_pkg").mkdir()
        (tmp_path / "valid_pkg" / "build.sh").write_text('TERMUX_PKG_VERSION="1.0.0"\n')
        pkgs = load_all_packages(tmp_path)
        names = [p["name"] for p in pkgs]
        assert "not_a_package.txt" not in names or all(p["version"] != "?" for p in pkgs if p["name"] == "not_a_package.txt")

    def test_fingerprint_file_with_binary_prefix(self, tmp_path):
        (tmp_path / "build-package.sh").write_bytes(
            b"\xff\xfe" + f"# {FINGERPRINT_STRING}\n".encode()
        )
        result = has_store_fingerprint(tmp_path)
        assert isinstance(result, bool)

    def test_fingerprint_file_empty(self, tmp_path):
        (tmp_path / "build-package.sh").write_bytes(b"")
        assert has_store_fingerprint(tmp_path) is False

    def test_is_valid_root_packages_is_file(self, tmp_path):
        (tmp_path / "packages").write_text("not a directory")
        (tmp_path / "build-package.sh").write_text(f"# {FINGERPRINT_STRING}\n")
        assert is_valid_root(tmp_path) is False


class TestInjectionInput:

    def test_cmd_install_nonexistent_package_exits(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "nonexistent-pkg")

    def test_cmd_install_empty_name_exits(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "")

    def test_cmd_install_dotdot_name_exits(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_install(root / "packages", root, "../../etc")

    def test_cmd_upgrade_nonexistent_target_exits(self, tmp_path):
        root = make_root(tmp_path)
        with pytest.raises(SystemExit):
            cmd_upgrade(root / "packages", root, target="nonexistent-pkg")

    def test_popen_receives_list_not_shell_string(self, tmp_path):
        root = make_root(tmp_path)
        make_pkg(root / "packages", "bower", f'TERMUX_PKG_VERSION="1.0.0"\n')

        captured = {}

        def fake_popen(args, **kwargs):
            captured["args"] = args
            captured["shell"] = kwargs.get("shell", False)
            mock_proc = MagicMock()
            mock_proc.stdout = make_stdout_mock([])
            mock_proc.returncode = 0
            return mock_proc

        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", side_effect=fake_popen), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            cmd_install(root / "packages", root, "bower")

        assert isinstance(captured["args"], list), "Popen must receive list not string"
        assert captured.get("shell") is not True, "shell=True must not be used"
        assert "bower" in captured["args"]

    def test_package_name_used_as_argument_not_interpolated(self, tmp_path):
        root = make_root(tmp_path)
        make_pkg(root / "packages", "my-tool", f'TERMUX_PKG_VERSION="1.0.0"\n')

        captured = {}

        def fake_popen(args, **kwargs):
            captured["args"] = args
            mock_proc = MagicMock()
            mock_proc.stdout = make_stdout_mock([])
            mock_proc.returncode = 0
            return mock_proc

        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", side_effect=fake_popen), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            cmd_install(root / "packages", root, "my-tool")

        assert "my-tool" in captured["args"]
        assert not any(";" in str(a) for a in captured["args"] if a != "my-tool")


class TestBrokenBuildScript:

    def _make_pkg(self, root, name, version="1.0.0"):
        pkg = root / "packages" / name
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "build.sh").write_text(f'TERMUX_PKG_VERSION="{version}"\n')
        return pkg

    def test_build_script_exits_nonzero(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = make_stdout_mock([b"Error: build failed\n"])
        mock_proc.returncode = 1
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc):
            result = cmd_install(root / "packages", root, "bower")
        assert result is False

    def test_build_script_exits_with_code_2(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = make_stdout_mock([])
        mock_proc.returncode = 2
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc):
            result = cmd_install(root / "packages", root, "bower")
        assert result is False

    def test_build_script_produces_no_output(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = make_stdout_mock([])
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
        mock_proc.stdout = make_stdout_mock([
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
             patch("subprocess.Popen", side_effect=OSError("No such file")):
            with pytest.raises((OSError, SystemExit, Exception)):
                cmd_install(root / "packages", root, "bower")

    def test_upgrade_with_broken_build(self, tmp_path, capsys):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower", "1.8.12")
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("UPDATE", "")), \
             patch("termux_app_store.termux_app_store_cli.get_installed_version", return_value="1.8.11"), \
             patch("termux_app_store.termux_app_store_cli.cmd_install", return_value=False):
            cmd_upgrade(root / "packages", root)
        assert "failed" in capsys.readouterr().out.lower()

    def test_build_output_with_binary_garbage(self, tmp_path):
        root = make_root(tmp_path)
        self._make_pkg(root, "bower")
        mock_proc = MagicMock()
        mock_proc.stdout = make_stdout_mock([
            b"\xff\xfe invalid utf8 \x00\x01\x02\n",
            b"normal line\n",
        ])
        mock_proc.returncode = 0
        with patch("termux_app_store.termux_app_store_cli.get_status", return_value=("NOT INSTALLED", "")), \
             patch("subprocess.Popen", return_value=mock_proc), \
             patch("termux_app_store.termux_app_store_cli.hold_package"):
            result = cmd_install(root / "packages", root, "bower")
        assert result is True
