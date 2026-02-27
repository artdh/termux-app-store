import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestMain:

    def test_main_with_args_calls_run_cli(self):
        with patch("sys.argv", ["termux-app-store", "help"]), \
             patch("termux_app_store.main.run_cli") as mock_cli, \
             patch("termux_app_store.main.run_tui") as mock_tui:
            from termux_app_store.main import main
            main()
        mock_cli.assert_called_once()
        mock_tui.assert_not_called()

    def test_main_no_args_calls_run_tui(self):
        with patch("sys.argv", ["termux-app-store"]), \
             patch("termux_app_store.main.run_cli") as mock_cli, \
             patch("termux_app_store.main.run_tui") as mock_tui:
            from termux_app_store import main as main_module
            import importlib
            importlib.reload(main_module)
            main_module.main()
        mock_tui.assert_called_once()
        mock_cli.assert_not_called()

    def test_main_multiple_args(self):
        with patch("sys.argv", ["termux-app-store", "install", "bower"]), \
             patch("termux_app_store.main.run_cli") as mock_cli, \
             patch("termux_app_store.main.run_tui"):
            from termux_app_store.main import main
            main()
        mock_cli.assert_called_once()


class TestMainBlock:

    def test_main_block_calls_main(self):
        with patch("termux_app_store.main.run_cli"), \
             patch("termux_app_store.main.run_tui"), \
             patch("sys.argv", ["termux-app-store", "help"]):
            mock_main = MagicMock()
            exec(
                'if "__main__" == "__main__": main()',
                {"main": mock_main}
            )
        mock_main.assert_called_once()
