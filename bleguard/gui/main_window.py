import os
import sys
import struct
from typing import Optional

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QFrame, QScrollArea,
    QSizePolicy, QGraphicsDropShadowEffect, QButtonGroup, QComboBox,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QSize
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QPixmap, QPainter, QBrush,
    QLinearGradient, QFontDatabase, QIcon,
)

from ..core import parse_capture, analyze, RISK_OK, RISK_WARN, RISK_CRITICAL, RISK_INFO
from ..core import CaptureSession, tshark_available
from .i18n import t, set_lang, get_lang, LANG_RU, LANG_EN

PALETTE = {
    'bg':           '#0D0F14',
    'bg_card':      '#111318',
    'bg_elevated':  '#171921',
    'border':       '#1E2030',
    'border_light': '#262840',
    'accent':       '#3A6BBF',
    'accent_dim':   '#1C3358',
    'text_primary': '#D4D7E3',
    'text_secondary': '#737894',
    'text_dim':     '#3E4258',
    'ok':           '#27A872',
    'ok_bg':        '#091A12',
    'warn':         '#B07A28',
    'warn_bg':      '#1A1208',
    'critical':     '#A84040',
    'critical_bg':  '#1A0C0C',
    'info':         '#5E7199',
    'info_bg':      '#0E1120',
    'btn_primary':  '#3A6BBF',
    'btn_danger':   '#A84040',
    'btn_neutral':  '#1E2030',
}

RISK_COLOR = {
    RISK_OK:       (PALETTE['ok'], PALETTE['ok_bg']),
    RISK_WARN:     (PALETTE['warn'], PALETTE['warn_bg']),
    RISK_CRITICAL: (PALETTE['critical'], PALETTE['critical_bg']),
    RISK_INFO:     (PALETTE['info'], PALETTE['info_bg']),
}

RISK_ICON = {
    RISK_OK:       '✓',
    RISK_WARN:     '⚠',
    RISK_CRITICAL: '✕',
    RISK_INFO:     'ℹ',
}

SCALE_OPTIONS = [('75%', 0.75), ('100%', 1.0), ('125%', 1.25), ('150%', 1.5)]


def _count_packets(path: str) -> int:
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if data.startswith(b'btsnoop\x00'):
            i, count = 16, 0
            while i + 24 <= len(data):
                incl_len = struct.unpack('>I', data[i + 4:i + 8])[0]
                i += 24 + incl_len
                count += 1
            return count
        elif data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            i, count = 24, 0
            while i + 16 <= len(data):
                incl_len = struct.unpack(endian + 'I', data[i + 8:i + 12])[0]
                i += 16 + incl_len
                count += 1
            return count
    except Exception:
        pass
    return 0


def _stylesheet(scale: float = 1.0) -> str:
    fs = int(13 * scale)
    return f"""
    QMainWindow, QWidget {{
        background-color: {PALETTE['bg']};
        color: {PALETTE['text_primary']};
        font-family: 'SF Mono', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
        font-size: {fs}px;
    }}
    QScrollArea {{
        border: none;
        background-color: transparent;
    }}
    QScrollBar:vertical {{
        background: {PALETTE['bg']};
        width: 6px;
        border-radius: 3px;
    }}
    QScrollBar::handle:vertical {{
        background: {PALETTE['border_light']};
        border-radius: 3px;
        min-height: 30px;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    QScrollBar:horizontal {{
        height: 0px;
    }}
    QLabel {{
        background: transparent;
        color: {PALETTE['text_primary']};
    }}
    QPushButton {{
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: 600;
        font-size: {fs}px;
        letter-spacing: 0.3px;
        border: none;
    }}
    QPushButton:disabled {{
        opacity: 0.4;
        color: {PALETTE['text_dim']};
        background: {PALETTE['bg_elevated']};
    }}
    QFrame#card {{
        background-color: {PALETTE['bg_card']};
        border: 1px solid {PALETTE['border']};
        border-radius: 12px;
    }}
    QFrame#separator {{
        background-color: {PALETTE['border']};
        max-height: 1px;
        min-height: 1px;
    }}
    QComboBox {{
        background: {PALETTE['bg_elevated']};
        color: {PALETTE['text_secondary']};
        border: 1px solid {PALETTE['border_light']};
        border-radius: 6px;
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 700;
    }}
    QComboBox:hover {{
        border-color: {PALETTE['accent']};
        color: {PALETTE['text_primary']};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 16px;
    }}
    QComboBox QAbstractItemView {{
        background: {PALETTE['bg_elevated']};
        color: {PALETTE['text_primary']};
        border: 1px solid {PALETTE['border_light']};
        selection-background-color: {PALETTE['accent_dim']};
        selection-color: {PALETTE['accent']};
        outline: none;
    }}
    """


def _make_button(text: str, color: str, hover_color: str = None, text_color: str = '#FFFFFF') -> QPushButton:
    if hover_color is None:
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        hover_color = f'#{min(r+20,255):02x}{min(g+20,255):02x}{min(b+20,255):02x}'
    btn = QPushButton(text)
    btn.setStyleSheet(f"""
        QPushButton {{
            background-color: {color};
            color: {text_color};
            border-radius: 8px;
            padding: 10px 22px;
            font-weight: 700;
            font-size: 13px;
            border: none;
        }}
        QPushButton:hover {{
            background-color: {hover_color};
        }}
        QPushButton:pressed {{
            background-color: {color};
            opacity: 0.8;
        }}
        QPushButton:disabled {{
            background-color: {PALETTE['bg_elevated']};
            color: {PALETTE['text_dim']};
        }}
    """)
    return btn


def _make_card(layout=None) -> QFrame:
    card = QFrame()
    card.setObjectName('card')
    card.setProperty('class', 'card')
    if layout:
        card.setLayout(layout)
    return card


class DotPulse(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._active = False
        self._step = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setText('●')
        self.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 14px;')

    def start(self):
        self._active = True
        self._timer.start(400)

    def stop(self):
        self._active = False
        self._timer.stop()
        self.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 14px;')

    def _tick(self):
        colors = [PALETTE['accent'], PALETTE['ok'], PALETTE['accent_dim']]
        c = colors[self._step % len(colors)]
        self.setStyleSheet(f'color: {c}; font-size: 14px;')
        self._step += 1


class AnalysisWorker(QThread):
    done = pyqtSignal(object, object)
    error = pyqtSignal(str)

    def __init__(self, filepath: str):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            parse_result = parse_capture(self.filepath)
            report = analyze(parse_result)
            self.done.emit(parse_result, report)
        except Exception as e:
            self.error.emit(str(e))


class MetricRow(QWidget):
    def __init__(self, label: str, value: str, risk: str, parent=None):
        super().__init__(parent)
        color, bg = RISK_COLOR.get(risk, (PALETTE['text_secondary'], PALETTE['bg_elevated']))
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 8, 14, 8)
        lay.setSpacing(12)

        lbl = QLabel(label)
        lbl.setStyleSheet(f'color: {PALETTE["text_secondary"]}; font-size: 12px;')
        lbl.setMinimumWidth(260)

        val = QLabel(value)
        val.setStyleSheet(f'color: {color}; font-size: 12px; font-weight: 600;')
        val.setWordWrap(True)

        lay.addWidget(lbl)
        lay.addWidget(val, 1)


class FindingCard(QWidget):
    def __init__(self, finding, lang: str, parent=None):
        super().__init__(parent)
        color, bg = RISK_COLOR.get(finding.level, (PALETTE['info'], PALETTE['info_bg']))
        icon = RISK_ICON.get(finding.level, '·')

        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {bg};
                border: 1px solid {PALETTE['border']};
                border-left: 2px solid {color}88;
                border-radius: 8px;
            }}
        """)
        inner = QVBoxLayout(frame)
        inner.setContentsMargins(14, 10, 14, 10)
        inner.setSpacing(4)

        title_text = finding.title_ru if lang == LANG_RU else finding.title_en
        detail_text = finding.detail_ru if lang == LANG_RU else finding.detail_en

        title_row = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f'color: {color}; font-size: 16px; font-weight: bold;')
        title_lbl = QLabel(title_text)
        title_lbl.setStyleSheet(f'color: {color}; font-size: 13px; font-weight: 700;')
        title_lbl.setWordWrap(True)
        title_row.addWidget(icon_lbl)
        title_row.addWidget(title_lbl, 1)
        inner.addLayout(title_row)

        if detail_text:
            detail_lbl = QLabel(detail_text)
            detail_lbl.setStyleSheet(f'color: {PALETTE["text_secondary"]}; font-size: 12px; line-height: 1.5;')
            detail_lbl.setWordWrap(True)
            inner.addWidget(detail_lbl)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 2, 0, 2)
        outer.addWidget(frame)


class ResultsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(10)
        self._layout.addStretch()

    def clear(self):
        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def show_report(self, parse_result, report, lang: str):
        self.clear()

        overall_color, overall_bg = RISK_COLOR.get(report.overall_risk, (PALETTE['info'], PALETTE['info_bg']))
        icon_text = RISK_ICON.get(report.overall_risk, '·')

        if report.overall_risk == RISK_OK:
            verdict_text = t('overall_safe')
        elif report.overall_risk == RISK_INFO:
            verdict_text = t('overall_info')
        elif report.overall_risk == RISK_WARN:
            verdict_text = t('overall_warn')
        else:
            verdict_text = t('overall_critical')

        verdict_card = QFrame()
        verdict_card.setStyleSheet(f"""
            QFrame {{
                background-color: {overall_bg};
                border: 1px solid {PALETTE['border']};
                border-radius: 12px;
            }}
        """)
        vc_lay = QHBoxLayout(verdict_card)
        vc_lay.setContentsMargins(20, 16, 20, 16)
        vc_lay.setSpacing(14)

        icon_big = QLabel(icon_text)
        icon_big.setStyleSheet(f'color: {overall_color}; font-size: 28px;')
        conn_label = QLabel(report.connection_type)
        conn_label.setStyleSheet(f'color: {PALETTE["text_secondary"]}; font-size: 12px;')
        verdict_lbl = QLabel(verdict_text)
        verdict_lbl.setStyleSheet(f'color: {overall_color}; font-size: 18px; font-weight: 700;')

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        text_col.addWidget(conn_label)
        text_col.addWidget(verdict_lbl)

        vc_lay.addWidget(icon_big)
        vc_lay.addLayout(text_col)
        vc_lay.addStretch()

        self._layout.addWidget(verdict_card)

        if report.overall_risk == RISK_CRITICAL:
            advice = QLabel(t('reconnect_advice'))
            advice.setStyleSheet(f"""
                color: {PALETTE['critical']};
                background: {PALETTE['critical_bg']};
                border: 1px solid {PALETTE['border']};
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 12px;
                font-weight: 600;
            """)
            advice.setWordWrap(True)
            self._layout.addWidget(advice)

        metrics_header = QLabel(t('section_metrics'))
        metrics_header.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding-top: 8px;')
        self._layout.addWidget(metrics_header)

        metrics_card = _make_card()
        mc_lay = QVBoxLayout()
        mc_lay.setContentsMargins(0, 4, 0, 4)
        mc_lay.setSpacing(0)
        metrics_card.setLayout(mc_lay)

        priority_order = ['connection_type', 'mac_address', 'encryption', 'key_size', 'ltk', 'mitm', 'secure_connections', 'packets_analyzed']
        ordered_metrics = []
        for k in priority_order:
            if k in report.metrics:
                ordered_metrics.append(report.metrics[k])
        for k, v in report.metrics.items():
            if k not in priority_order:
                ordered_metrics.append(v)

        for i, (label, value, risk) in enumerate(ordered_metrics):
            row = MetricRow(label, value, risk)
            if i % 2 == 0:
                row.setStyleSheet(f'background-color: {PALETTE["bg_elevated"]}; border-radius: 4px;')
            mc_lay.addWidget(row)

        self._layout.addWidget(metrics_card)

        findings_header = QLabel(t('section_findings'))
        findings_header.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding-top: 8px;')
        self._layout.addWidget(findings_header)

        for finding in report.findings:
            card = FindingCard(finding, lang)
            self._layout.addWidget(card)

        self._layout.addStretch()

    def show_message(self, text: str, color: str = None):
        self.clear()
        if color is None:
            color = PALETTE['text_secondary']
        lbl = QLabel(text)
        lbl.setStyleSheet(f'color: {color}; font-size: 13px; padding: 20px;')
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setWordWrap(True)
        self._layout.addWidget(lbl)
        self._layout.addStretch()


class MainWindow(QMainWindow):
    _status_update = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._lang = LANG_RU
        self._scale = 1.0
        self._capture: Optional[CaptureSession] = None
        self._capture_file: Optional[str] = None
        self._worker: Optional[AnalysisWorker] = None
        self._mode = 'idle'

        self._packet_timer = QTimer(self)
        self._packet_timer.setInterval(1500)
        self._packet_timer.timeout.connect(self._update_packet_count)

        self.setAcceptDrops(True)

        self._setup_ui()
        self._apply_theme()
        self._update_texts()
        self._update_button_states()

    def _setup_ui(self):
        self.setMinimumSize(820, 680)
        self.resize(900, 740)

        root = QWidget()
        self.setCentralWidget(root)
        root_lay = QVBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        self._header = self._build_header()
        root_lay.addWidget(self._header)

        sep = QFrame()
        sep.setObjectName('separator')
        root_lay.addWidget(sep)

        content = QWidget()
        content.setStyleSheet(f'background: {PALETTE["bg"]};')
        content_lay = QHBoxLayout(content)
        content_lay.setContentsMargins(20, 20, 20, 20)
        content_lay.setSpacing(16)

        left_panel = self._build_left_panel()
        content_lay.addWidget(left_panel, 0)

        right_panel = self._build_right_panel()
        content_lay.addWidget(right_panel, 1)

        root_lay.addWidget(content, 1)

        self._build_statusbar()

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet(f'background: {PALETTE["bg_card"]}; border-bottom: 1px solid {PALETTE["border"]};')

        lay = QHBoxLayout(header)
        lay.setContentsMargins(24, 0, 24, 0)
        lay.setSpacing(12)

        app_name = QLabel('BLEGuard')
        app_name.setStyleSheet(f'color: {PALETTE["text_primary"]}; font-size: 18px; font-weight: 700; letter-spacing: -0.5px;')

        lay.addWidget(app_name)
        lay.addStretch()

        self._dot_pulse = DotPulse()
        lay.addWidget(self._dot_pulse)

        self._mode_lbl = QLabel()
        self._mode_lbl.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 11px;')
        lay.addWidget(self._mode_lbl)

        sep_v = QFrame()
        sep_v.setFrameShape(QFrame.VLine)
        sep_v.setStyleSheet(f'color: {PALETTE["border"]};')
        lay.addWidget(sep_v)

        self._lang_btn_ru = QPushButton('RU')
        self._lang_btn_en = QPushButton('EN')
        for btn, code in [(self._lang_btn_ru, LANG_RU), (self._lang_btn_en, LANG_EN)]:
            btn.setFixedSize(36, 28)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {'transparent' if code != self._lang else PALETTE['accent_dim']};
                    color: {PALETTE['accent'] if code == self._lang else PALETTE['text_dim']};
                    border: 1px solid {'transparent' if code != self._lang else PALETTE['accent']};
                    border-radius: 6px;
                    font-size: 11px;
                    font-weight: 700;
                    padding: 0;
                }}
                QPushButton:hover {{
                    color: {PALETTE['text_primary']};
                    border-color: {PALETTE['border_light']};
                }}
            """)
        self._lang_btn_ru.clicked.connect(lambda: self._set_lang(LANG_RU))
        self._lang_btn_en.clicked.connect(lambda: self._set_lang(LANG_EN))
        lay.addWidget(self._lang_btn_ru)
        lay.addWidget(self._lang_btn_en)

        sep_v2 = QFrame()
        sep_v2.setFrameShape(QFrame.VLine)
        sep_v2.setStyleSheet(f'color: {PALETTE["border"]};')
        lay.addWidget(sep_v2)

        self._scale_combo = QComboBox()
        self._scale_combo.setFixedSize(72, 28)
        for label, _ in SCALE_OPTIONS:
            self._scale_combo.addItem(label)
        self._scale_combo.setCurrentIndex(1)
        self._scale_combo.currentIndexChanged.connect(
            lambda i: self._set_scale(SCALE_OPTIONS[i][1])
        )
        lay.addWidget(self._scale_combo)

        return header

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        panel.setFixedWidth(220)
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        steps_card = _make_card()
        sc_lay = QVBoxLayout()
        sc_lay.setContentsMargins(16, 14, 16, 14)
        sc_lay.setSpacing(10)
        steps_card.setLayout(sc_lay)

        self._steps_title = QLabel(t('how_to_use'))
        self._steps_title.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;')
        sc_lay.addWidget(self._steps_title)

        self._step_labels = []
        for key in ['step1', 'step2', 'step3']:
            lbl = QLabel(t(key))
            lbl.setStyleSheet(f'color: {PALETTE["text_secondary"]}; font-size: 11px; line-height: 1.6;')
            lbl.setWordWrap(True)
            sc_lay.addWidget(lbl)
            self._step_labels.append((key, lbl))

        lay.addWidget(steps_card)

        sep = QFrame()
        sep.setObjectName('separator')
        lay.addWidget(sep)

        self._btn_start = _make_button('', PALETTE['btn_primary'])
        self._btn_start.clicked.connect(self._on_start)
        lay.addWidget(self._btn_start)

        self._btn_stop = _make_button('', PALETTE['btn_neutral'], text_color=PALETTE['text_primary'])
        self._btn_stop.setStyleSheet(f"""
            QPushButton {{
                background: {PALETTE['bg_elevated']};
                color: {PALETTE['text_primary']};
                border: 1px solid {PALETTE['border_light']};
                border-radius: 8px;
                padding: 10px 22px;
                font-weight: 700;
                font-size: 13px;
            }}
            QPushButton:hover {{
                border-color: {PALETTE['accent']};
                color: {PALETTE['accent']};
            }}
            QPushButton:disabled {{
                background: {PALETTE['bg_elevated']};
                color: {PALETTE['text_dim']};
                border-color: {PALETTE['border']};
            }}
        """)
        self._btn_stop.clicked.connect(self._on_stop)
        lay.addWidget(self._btn_stop)

        self._btn_check = _make_button('', PALETTE['ok'], hover_color='#25A870')
        self._btn_check.clicked.connect(self._on_check)
        lay.addWidget(self._btn_check)

        sep2 = QFrame()
        sep2.setObjectName('separator')
        lay.addWidget(sep2)

        self._btn_load = _make_button('', PALETTE['bg_elevated'], text_color=PALETTE['accent'])
        self._btn_load.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {PALETTE['accent']};
                border: 1px solid {PALETTE['accent_dim']};
                border-radius: 8px;
                padding: 10px 22px;
                font-weight: 600;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background: {PALETTE['accent_dim']};
                color: {PALETTE['text_primary']};
            }}
        """)
        self._btn_load.clicked.connect(self._on_load_file)
        lay.addWidget(self._btn_load)

        self._btn_clear = _make_button('', PALETTE['bg_elevated'], text_color=PALETTE['text_secondary'])
        self._btn_clear.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {PALETTE['text_secondary']};
                border: 1px solid {PALETTE['border']};
                border-radius: 8px;
                padding: 8px 22px;
                font-weight: 600;
                font-size: 12px;
            }}
            QPushButton:hover {{
                border-color: {PALETTE['border_light']};
                color: {PALETTE['text_primary']};
            }}
        """)
        self._btn_clear.clicked.connect(self._on_clear)
        lay.addWidget(self._btn_clear)

        lay.addStretch()

        return panel

    def _build_right_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName('card')
        outer_lay = QVBoxLayout(panel)
        outer_lay.setContentsMargins(0, 0, 0, 0)
        outer_lay.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.NoFrame)

        scroll_content = QWidget()
        scroll_content.setStyleSheet(f'background: {PALETTE["bg_card"]};')
        self._results_panel = ResultsPanel(scroll_content)
        inner_lay = QVBoxLayout(scroll_content)
        inner_lay.setContentsMargins(16, 16, 16, 16)
        inner_lay.addWidget(self._results_panel)

        scroll.setWidget(scroll_content)
        outer_lay.addWidget(scroll)

        return panel

    def _build_statusbar(self):
        self._status_lbl = QLabel(t('status_idle'))
        self._status_lbl.setStyleSheet(f'color: {PALETTE["text_dim"]}; font-size: 11px; padding: 0 24px;')
        sb = self.statusBar()
        sb.setStyleSheet(f'background: {PALETTE["bg_card"]}; border-top: 1px solid {PALETTE["border"]};')
        sb.addWidget(self._status_lbl, 1)

    def _apply_theme(self):
        self.setStyleSheet(_stylesheet(self._scale))
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor(PALETTE['bg']))
        pal.setColor(QPalette.WindowText, QColor(PALETTE['text_primary']))
        QApplication.setPalette(pal)

    def _update_texts(self):
        self.setWindowTitle(t('app_title'))
        self._btn_start.setText(t('btn_start'))
        self._btn_stop.setText(t('btn_stop'))
        self._btn_check.setText(t('btn_check'))
        self._btn_load.setText(t('btn_load_file'))
        self._btn_clear.setText(t('btn_clear'))
        self._steps_title.setText(t('how_to_use'))
        for key, lbl in self._step_labels:
            lbl.setText(t(key))
        self._update_mode_label()
        self._update_lang_buttons()

    def _update_lang_buttons(self):
        for btn, code in [(self._lang_btn_ru, LANG_RU), (self._lang_btn_en, LANG_EN)]:
            active = code == self._lang
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {'transparent' if not active else PALETTE['accent_dim']};
                    color: {PALETTE['accent'] if active else PALETTE['text_dim']};
                    border: 1px solid {'transparent' if not active else PALETTE['accent']};
                    border-radius: 6px;
                    font-size: 11px;
                    font-weight: 700;
                    padding: 0;
                }}
                QPushButton:hover {{
                    color: {PALETTE['text_primary']};
                    border-color: {PALETTE['border_light']};
                }}
            """)

    def _update_mode_label(self):
        if self._capture_file and not (self._capture and self._capture.is_running):
            self._mode_lbl.setText(t('mode_file'))
        elif self._capture and self._capture.is_running:
            self._mode_lbl.setText(t('mode_live'))
        else:
            self._mode_lbl.setText('')

    def _update_button_states(self):
        capturing = bool(self._capture and self._capture.is_running)
        has_file = bool(self._capture_file)
        analyzing = self._mode == 'analyzing'

        self._btn_start.setEnabled(not capturing and not analyzing)
        self._btn_stop.setEnabled(capturing)
        self._btn_check.setEnabled(has_file and not analyzing)
        self._btn_clear.setEnabled(not capturing and not analyzing)
        self._btn_load.setEnabled(not capturing and not analyzing)

    def _set_lang(self, lang: str):
        self._lang = lang
        set_lang(lang)
        self._update_texts()
        if self._mode == 'results' and hasattr(self, '_last_parse_result'):
            self._last_report = analyze(self._last_parse_result)
            self._results_panel.show_report(self._last_parse_result, self._last_report, lang)

    def _set_scale(self, scale: float):
        self._scale = scale
        self.setStyleSheet(_stylesheet(scale))
        base_w, base_h = 900, 740
        min_w, min_h = 820, 680
        self.setMinimumSize(int(min_w * scale), int(min_h * scale))
        self.resize(int(base_w * scale), int(base_h * scale))
        idx = next((i for i, (_, s) in enumerate(SCALE_OPTIONS) if abs(s - scale) < 0.01), 1)
        self._scale_combo.blockSignals(True)
        self._scale_combo.setCurrentIndex(idx)
        self._scale_combo.blockSignals(False)

    def _set_status(self, text: str, color: str = None):
        if color is None:
            color = PALETTE['text_dim']
        self._status_lbl.setText(text)
        self._status_lbl.setStyleSheet(f'color: {color}; font-size: 11px; padding: 0 24px;')

    def _on_start(self):
        self._capture = CaptureSession()
        self._capture_file = None

        if not tshark_available():
            self._set_status(t('tshark_missing'), PALETTE['warn'])

        if self._capture.start():
            if self._capture.capture_file:
                self._capture_file = self._capture.capture_file
            self._dot_pulse.start()
            self._set_status(t('status_capturing'), PALETTE['accent'])
            self._results_panel.show_message(t('capturing_hint'), PALETTE['text_secondary'])
            self._packet_timer.start()
            self._update_button_states()
            self._update_mode_label()

    def _on_stop(self):
        if not self._capture:
            return
        self._packet_timer.stop()
        captured_path = self._capture.stop()
        if captured_path and os.path.exists(captured_path) and os.path.getsize(captured_path) > 0:
            self._capture_file = captured_path
        self._dot_pulse.stop()
        self._set_status(t('status_ready_to_check'), PALETTE['ok'])
        self._update_button_states()
        self._update_mode_label()

    def _on_check(self):
        if not self._capture_file:
            self._results_panel.show_message(t('no_data'), PALETTE['warn'])
            return

        if self._capture and self._capture.is_running:
            self._on_stop()

        self._mode = 'analyzing'
        self._set_status(t('status_analyzing'), PALETTE['accent'])
        self._results_panel.show_message(t('status_analyzing'), PALETTE['accent'])
        self._update_button_states()

        self._worker = AnalysisWorker(self._capture_file)
        self._worker.done.connect(self._on_analysis_done)
        self._worker.error.connect(self._on_analysis_error)
        self._worker.start()

    def _on_load_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            t('file_dialog_title'),
            os.path.expanduser('~'),
            'BTSnoop / PCAP (*.btsnoop *.pcap *.pcapng);;All files (*)',
        )
        if not path:
            return
        self._capture_file = path
        self._mode = 'file'
        self._set_status(f'{t("loaded_file")}: {os.path.basename(path)}', PALETTE['accent'])
        self._update_button_states()
        self._update_mode_label()
        self._on_check()

    def _on_clear(self):
        if self._capture:
            self._capture.cleanup()
            self._capture = None
        self._capture_file = None
        self._mode = 'idle'
        self._results_panel.clear()
        self._set_status(t('status_idle'))
        self._update_button_states()
        self._update_mode_label()

    def _on_analysis_done(self, parse_result, report):
        self._mode = 'results'
        self._last_parse_result = parse_result
        self._last_report = report
        self._results_panel.show_report(parse_result, report, self._lang)
        color = {RISK_OK: PALETTE['ok'], RISK_WARN: PALETTE['warn'], RISK_CRITICAL: PALETTE['critical']}.get(report.overall_risk, PALETTE['text_dim'])
        self._set_status(t('status_done'), color)
        self._update_button_states()

    def _on_analysis_error(self, error_msg: str):
        self._mode = 'idle'
        self._results_panel.show_message(f'Error: {error_msg}', PALETTE['critical'])
        self._set_status(f'Error: {error_msg}', PALETTE['critical'])
        self._update_button_states()

    def _update_packet_count(self):
        if not (self._capture and self._capture.is_running and self._capture_file):
            return
        if not os.path.exists(self._capture_file):
            return
        count = _count_packets(self._capture_file)
        label = 'пак.' if get_lang() == LANG_RU else 'pkts'
        self._set_status(f'{t("status_capturing")} — {count} {label}', PALETTE['accent'])

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if any(u.toLocalFile().lower().endswith(('.btsnoop', '.pcap', '.pcapng')) for u in urls):
                event.acceptProposedAction()
                return
        event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        for url in urls:
            path = url.toLocalFile()
            if path.lower().endswith(('.btsnoop', '.pcap', '.pcapng')) and os.path.isfile(path):
                self._capture_file = path
                self._mode = 'file'
                self._set_status(f'{t("loaded_file")}: {os.path.basename(path)}', PALETTE['accent'])
                self._update_button_states()
                self._update_mode_label()
                self._on_check()
                break

    def closeEvent(self, event):
        if self._capture and self._capture.is_running:
            self._capture.stop()
            self._capture.cleanup()
        super().closeEvent(event)


def run_app():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName('BLEGuard')

    for _font_path in [
        '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
        '/usr/share/fonts/dejavu/DejaVuSansMono.ttf',
        '/usr/share/fonts/TTF/DejaVuSansMono.ttf',
    ]:
        if os.path.isfile(_font_path):
            QFontDatabase.addApplicationFont(_font_path)
            break

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
