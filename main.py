## @file main.py
#  @brief Запуск BLEGuard.
#
#  @details Добавляет каталог в sys.path и запускает графический
#           интерфейс.
#           Запуск: @code python main.py @endcode
#
#  @author  RainL1
#  @version 2.0
#  @date    2026

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bleguard.gui import run_app

if __name__ == '__main__':
    run_app()
