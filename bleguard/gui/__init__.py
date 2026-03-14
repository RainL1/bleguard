## @file __init__.py
#  @brief Публичный API подпакета bleguard.gui.
#
#  @details Экспортирует `run_app()` — основную точку запуска GUI,
#           `MainWindow` — для прямого создания в тестах или встраивания,
#           а также функции интернационализации из модуля i18n.
#
#  @package bleguard.gui

from .main_window import run_app, MainWindow
from .i18n import t, set_lang, get_lang
