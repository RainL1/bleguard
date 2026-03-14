## @file capture.py
#  @brief Управляет живым захватом Bluetooth-трафика через tshark.
#
#  @details Запускает tshark на интерфейсе bluetooth-monitor и пишет трафик
#           во временный файл. Если tshark не найден, переходит в ручной режим.
#
#  @author  RainL1
#  @version 2.0
#  @date    2026

import subprocess
import tempfile
import os
import signal
import time
from typing import Optional, Callable


class CaptureSession:
    """@brief Сессия живого захвата Bluetooth-трафика.

    @details Управляет дочерним процессом tshark. Если tshark недоступен,
             сессия переходит в ручной режим — файл не создаётся, но
             считается запущенной.

    @note Не потокобезопасен; вызывайте start() и stop() из одного потока.
    """

    def __init__(self):
        """@brief Инициализирует сессию в состоянии «остановлена»."""
        self._proc: Optional[subprocess.Popen] = None
        self._capture_file: Optional[str] = None
        self._running = False
        ## Callback для передачи статусных сообщений пользователю.
        self.on_status: Optional[Callable[[str], None]] = None

    def _emit(self, msg: str):
        """@brief Передаёт строку статуса в зарегистрированный callback.

        @param msg  Сообщение о статусе.
        """
        if self.on_status:
            self.on_status(msg)

    def start(self) -> bool:
        """@brief Запускает захват трафика.

        @details Создаёт временный файл и запускает tshark на интерфейсе
                 bluetooth-monitor. Если tshark не найден — ручной режим.

        @return True при успешном запуске.
        """
        if self._running:
            return True

        tmpfile = tempfile.NamedTemporaryFile(suffix='.btsnoop', delete=False)
        self._capture_file = tmpfile.name
        tmpfile.close()

        tshark_path = _find_tshark()
        if tshark_path:
            try:
                cmd = [
                    tshark_path,
                    '-i', 'bluetooth-monitor',
                    '-F', 'pcap',
                    '-w', self._capture_file,
                ]
                self._proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                self._running = True
                self._emit('tshark capture started')
                return True
            except Exception as e:
                self._emit(f'tshark error: {e}')

        self._running = True
        self._emit('Capture session started (manual mode)')
        return True

    def stop(self) -> Optional[str]:
        """@brief Останавливает захват и возвращает путь к файлу.

        @details Посылает SIGINT процессу tshark и ждёт до 3 секунд,
                 затем завершает принудительно.

        @return Путь к файлу захвата или None.
        """
        self._running = False
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.send_signal(signal.SIGINT)
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None
        return self._capture_file

    @property
    def is_running(self) -> bool:
        """@brief True, если сессия захвата активна."""
        return self._running

    @property
    def capture_file(self) -> Optional[str]:
        """@brief Путь к временному файлу захвата или None."""
        return self._capture_file

    def cleanup(self):
        """@brief Удаляет временный файл захвата с диска."""
        if self._capture_file and os.path.exists(self._capture_file):
            try:
                os.unlink(self._capture_file)
            except Exception:
                pass
        self._capture_file = None


def _find_tshark() -> Optional[str]:
    """@brief Ищет исполняемый файл tshark в стандартных местах.

    @return Путь к tshark или None, если не найден.
    """
    for path in ['/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark']:
        if os.path.isfile(path):
            return path
    try:
        result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def tshark_available() -> bool:
    """@brief True, если tshark доступен в системе."""
    return _find_tshark() is not None
