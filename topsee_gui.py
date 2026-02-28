#!/usr/bin/env python3
"""
Topsee / Tianshitong Camera Discovery GUI
==========================================
Runs topsee_udp_discover.py in the background, streams its output to a
terminal-style log pane, then populates a snapshot grid with JPEG thumbnails
from each discovered camera.

Authors: Claude (Anthropic) — code heavy lifting

Contributors: silvije2 (https://github.com/silvije2) — feature direction

Requirements:
    sudo apt install python3-pyqt6 ffmpeg        # or: python3-pyqt5

Run:
    sudo python3 topsee_gui.py
    (sudo needed so the discovery script can bind UDP port 3001)
"""

import sys, os, re, urllib.request
from collections import deque

# ── Qt import with PyQt5 fallback ─────────────────────────────────────────────
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QPlainTextEdit, QScrollArea, QLabel, QFrame,
        QGridLayout, QSplitter, QMenu, QFileDialog,
    )
    from PyQt6.QtCore  import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui   import QFont, QPixmap, QColor, QPalette, QImage
    ALIGN_CENTER = Qt.AlignmentFlag.AlignCenter
    ORIENT_V     = Qt.Orientation.Vertical
    KEEP_AR      = Qt.AspectRatioMode.KeepAspectRatio
    SMOOTH       = Qt.TransformationMode.SmoothTransformation
    STYLED_PANEL = QFrame.Shape.StyledPanel
except ImportError:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QPlainTextEdit, QScrollArea, QLabel, QFrame,
        QGridLayout, QSplitter, QMenu, QFileDialog,
    )
    from PyQt5.QtCore  import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui   import QFont, QPixmap, QColor, QPalette, QImage
    ALIGN_CENTER = Qt.AlignCenter
    ORIENT_V     = Qt.Vertical
    KEEP_AR      = Qt.KeepAspectRatio
    SMOOTH       = Qt.SmoothTransformation
    STYLED_PANEL = QFrame.StyledPanel


SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
DISCOVER_PY = os.path.join(SCRIPT_DIR, 'topsee_udp_discover.py')
COLS        = 4
TILE_W      = 400
TILE_H      = 270


# ─────────────────────────────────────────────────────────────────────────────
# Discovery worker — subprocess in its own QThread
# ─────────────────────────────────────────────────────────────────────────────
class DiscoverWorker(QThread):
    line   = pyqtSignal(str)
    camera = pyqtSignal(str, str, str)   # ip, snapshot_url, rtsp_url
    done   = pyqtSignal(int)

    def __init__(self, script_path):
        super().__init__()
        self.script_path = script_path

    def run(self):
        import subprocess
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        try:
            proc = subprocess.Popen(
                [sys.executable, '-u', self.script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=env,
            )
        except Exception as e:
            self.line.emit(f'[ERROR] {e}')
            self.done.emit(1)
            return

        current_ip   = None
        current_rtsp = None
        current_user = ''
        current_pass = ''
        cameras_done = set()

        for raw in proc.stdout:
            line = raw.rstrip('\n')
            self.line.emit(line)

            # new camera block separator resets context
            if re.match(r'\s*[=═]{6,}', line):
                current_ip   = None
                current_rtsp = None
                current_user = ''
                current_pass = ''
                continue

            # "  192.168.1.2  —  ModelName"
            m = re.match(r'\s{2}(\d{1,3}(?:\.\d{1,3}){3})\s+[—–\-]', line)
            if m:
                current_ip   = m.group(1)
                current_rtsp = None
                current_user = ''
                current_pass = ''
                continue

            # "[+] Discovered: 192.168.1.2"
            m = re.search(r'Discovered:\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
            if m:
                current_ip = m.group(1)
                continue

            # "  TCP/ONVIF Login  : admin / 123456"
            m = re.search(r'(?:TCP|ONVIF|Login)\s*[:/]\s*\S.*?:\s*(\S+)\s*/\s*(\S*)', line)
            if m:
                current_user = m.group(1)
                current_pass = m.group(2)
                continue

            # "  Main Stream       : rtsp://..."
            m = re.search(r'Main Stream\s*:\s*(rtsp://\S+)', line)
            if m:
                current_rtsp = m.group(1).rstrip('.,;)').replace('&amp;', '&')
                continue

            # "  Main Snapshot     : http://..."
            m = re.search(r'Main Snapshot\s*:\s*(https?://\S+)', line)
            if m:
                url = m.group(1).rstrip('.,;)')
                ip  = current_ip
                if not ip:
                    mu = re.search(r'https?://(\d{1,3}(?:\.\d{1,3}){3})', url)
                    ip = mu.group(1) if mu else None
                if ip and (ip, url) not in cameras_done:
                    cameras_done.add((ip, url))
                    # Embed credentials into RTSP URL if we have them
                    rtsp = current_rtsp or ''
                    if rtsp and current_user:
                        # rtsp://host:port/path  →  rtsp://user:pass@host:port/path
                        rtsp = re.sub(
                            r'^(rtsp://)',
                            f'rtsp://{current_user}:{current_pass}@',
                            rtsp,
                        )
                    self.camera.emit(ip, url, rtsp)

        proc.wait()
        self.done.emit(proc.returncode)


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot fetcher — with retries and longer timeout
# ─────────────────────────────────────────────────────────────────────────────
class SnapshotFetcher(QThread):
    ready = pyqtSignal(bytes)
    error = pyqtSignal(str)

    MAX_TRIES = 3
    TIMEOUT   = 15   # cameras can be slow; 407 often clears on retry

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        import time
        last_err = ''
        for attempt in range(self.MAX_TRIES):
            if attempt:
                time.sleep(1.5 * attempt)   # 0 / 1.5 / 3 s back-off
            try:
                req = urllib.request.Request(self.url,
                          headers={'User-Agent': 'TopseeGUI/1.0'})
                with urllib.request.urlopen(req, timeout=self.TIMEOUT) as r:
                    self.ready.emit(r.read())
                    return
            except Exception as e:
                last_err = str(e)
        self.error.emit(last_err)


# ─────────────────────────────────────────────────────────────────────────────
# RTSP frame grabber — ffmpeg stdout pipe, no temp file
# ─────────────────────────────────────────────────────────────────────────────
class RtspFetcher(QThread):
    ready = pyqtSignal(bytes)
    error = pyqtSignal(str)

    def __init__(self, rtsp_url):
        super().__init__()
        self.rtsp_url = rtsp_url

    def run(self):
        import subprocess, shutil
        if not shutil.which('ffmpeg'):
            self.error.emit('ffmpeg not found')
            return
        print(f'[RTSP] trying: {self.rtsp_url}', flush=True)
        cmd = [
            'ffmpeg', '-loglevel', 'error',
            '-rtsp_transport', 'tcp',
            '-i', self.rtsp_url,
            '-vf', 'select=eq(pict_type\\,PICT_TYPE_I)',
            '-frames:v', '1',
            '-f', 'mjpeg',
            'pipe:1',
        ]
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            if result.returncode == 0 and result.stdout:
                self.ready.emit(result.stdout)
            else:
                err = result.stderr.decode(errors='replace').strip()
                print(f'[RTSP] ffmpeg stderr:\n{err}', flush=True)
                self.error.emit(f'ffmpeg: {err[-120:]}' if err else 'ffmpeg: no output')
        except subprocess.TimeoutExpired:
            self.error.emit('ffmpeg timed out')
        except Exception as e:
            self.error.emit(str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Fullscreen image viewer (opens on double-click)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from PyQt6.QtWidgets import QDialog
except ImportError:
    from PyQt5.QtWidgets import QDialog

class ImageViewer(QDialog):
    def __init__(self, pixmap, ip, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f'Camera  {ip}')
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose
                          if hasattr(Qt, 'WidgetAttribute')
                          else Qt.WA_DeleteOnClose)
        self.setStyleSheet('background:#000;')

        # Fill ~90 % of the available screen
        screen = QApplication.primaryScreen().availableGeometry()
        max_w  = int(screen.width()  * 0.92)
        max_h  = int(screen.height() * 0.92)
        scaled = pixmap.scaled(max_w, max_h, KEEP_AR, SMOOTH)

        lbl = QLabel()
        lbl.setPixmap(scaled)
        lbl.setAlignment(ALIGN_CENTER)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(lbl)

        self.resize(scaled.width(), scaled.height())
        # Centre on screen
        self.move(screen.x() + (screen.width()  - scaled.width())  // 2,
                  screen.y() + (screen.height() - scaled.height()) // 2)

    def keyPressEvent(self, e):
        self.close()

    def mouseDoubleClickEvent(self, e):
        self.close()


# ─────────────────────────────────────────────────────────────────────────────
# Camera tile
# ─────────────────────────────────────────────────────────────────────────────
class CameraTile(QFrame):
    def __init__(self, ip, snap_url, rtsp_url='', parent=None):
        super().__init__(parent)
        self.ip        = ip
        self.snap_url  = snap_url
        self.rtsp_url  = rtsp_url
        self._fetchers  = []
        self._pixmap    = None
        self._raw_bytes = None

        self.setFixedSize(TILE_W, TILE_H + 30)
        self.setFrameShape(STYLED_PANEL)
        self.setStyleSheet("""
            CameraTile {
                background: #181b22;
                border: 1px solid #2a2f3c;
                border-radius: 6px;
            }
            CameraTile:hover { border-color: #4a85a8; }
        """)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self.img = QLabel('fetching…')
        self.img.setFixedSize(TILE_W, TILE_H)
        self.img.setAlignment(ALIGN_CENTER)
        self.img.setFont(QFont('Monospace', 8))
        self.img.setStyleSheet(
            'background:#0c0e13; color:#445; border-radius:6px 6px 0 0;')
        lay.addWidget(self.img)

        lbl = QLabel(ip)
        lbl.setFixedHeight(30)
        lbl.setAlignment(ALIGN_CENTER)
        lbl.setFont(QFont('Monospace', 9))
        lbl.setStyleSheet(
            'background:#101318; color:#6aafd4;'
            'border-radius:0 0 6px 6px; padding:2px;')
        lay.addWidget(lbl)

        self._fetch()

    def _fetch(self):
        f = SnapshotFetcher(self.snap_url)
        f.ready.connect(self._on_ready)
        f.error.connect(self._on_error)
        f.finished.connect(lambda: self._fetchers.remove(f)
                           if f in self._fetchers else None)
        self._fetchers.append(f)
        f.start()

    def _on_ready(self, data):
        img = QImage()
        img.loadFromData(data)
        if img.isNull():
            self._on_error('bad image data')
            return
        self._pixmap    = QPixmap.fromImage(img)   # full-res, for viewer
        self._raw_bytes = data                     # original file bytes, for save
        px = self._pixmap.scaled(TILE_W, TILE_H, KEEP_AR, SMOOTH)
        self.img.setPixmap(px)
        self.img.setStyleSheet(
            'background:#0c0e13; border-radius:6px 6px 0 0;')

    def _on_error(self, msg):
        if self.rtsp_url:
            # HTTP snapshot failed — try grabbing a frame from the RTSP stream
            self.img.setText('snapshot failed\ntrying RTSP…')
            self.img.setStyleSheet(
                'background:#0c0e13; color:#7a8a6a;'
                'border-radius:6px 6px 0 0;')
            f = RtspFetcher(self.rtsp_url)
            f.ready.connect(self._on_ready)
            f.error.connect(self._on_rtsp_error)
            f.finished.connect(lambda: self._fetchers.remove(f)
                               if f in self._fetchers else None)
            self._fetchers.append(f)
            f.start()
        else:
            self._show_error(msg)

    def _on_rtsp_error(self, msg):
        self._show_error(f'HTTP+RTSP failed: {msg}')

    def _show_error(self, msg):
        self._pixmap    = None
        self._raw_bytes = None
        self.img.setText(f'⚠  {msg}')
        self.img.setStyleSheet(
            'background:#0c0e13; color:#8a4040;'
            'border-radius:6px 6px 0 0;')

    def refresh(self):
        self.img.setText('fetching…')
        self.img.setStyleSheet(
            'background:#0c0e13; color:#445; border-radius:6px 6px 0 0;')
        self._fetch()

    def mouseDoubleClickEvent(self, _event):
        if self._pixmap and not self._pixmap.isNull():
            v = ImageViewer(self._pixmap, self.ip, self.window())
            v.exec() if hasattr(v, 'exec') else v.exec_()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background: #1a1d26; color: #c0c4d0;
                border: 1px solid #353a48; border-radius: 4px;
                padding: 4px 0;
            }
            QMenu::item { padding: 6px 20px; }
            QMenu::item:selected { background: #285070; }
            QMenu::item:disabled { color: #444; }
            QMenu::separator { background: #353a48; height: 1px; margin: 3px 8px; }
        """)

        act_save = menu.addAction(f'💾  Save snapshot  ({self.ip})')
        act_save.setEnabled(self._raw_bytes is not None)
        menu.addSeparator()
        act_view = menu.addAction('🔍  View fullscreen')
        act_view.setEnabled(self._pixmap is not None)
        act_refresh = menu.addAction('↺  Refresh')

        chosen = menu.exec(event.globalPos()) if hasattr(menu, 'exec') \
                 else menu.exec_(event.globalPos())

        if chosen == act_save:
            self._save_snapshot()
        elif chosen == act_view:
            v = ImageViewer(self._pixmap, self.ip, self.window())
            v.exec() if hasattr(v, 'exec') else v.exec_()
        elif chosen == act_refresh:
            self.refresh()

    def _save_snapshot(self):
        if not self._raw_bytes:
            return
        from datetime import datetime
        ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ip  = self.ip.replace('.', '_')
        default  = os.path.join(os.path.expanduser('~'),
                                f'{safe_ip}_{ts}.jpg')
        path, _  = QFileDialog.getSaveFileName(
            self, 'Save snapshot', default,
            'JPEG image (*.jpg *.jpeg);;PNG image (*.png);;All files (*)'
        )
        if not path:
            return
        if path.lower().endswith('.png'):
            # re-encode as PNG via Qt
            self._pixmap.save(path, 'PNG')
        else:
            # write the original bytes untouched
            with open(path, 'wb') as f:
                f.write(self._raw_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Topsee Camera Discovery')
        self.resize(1200, 820)
        self.setMinimumSize(800, 560)

        self._worker    = None
        self._tiles     = {}
        self._tile_pos  = 0
        self._log_queue = deque()
        self._cur_cols  = 4   # updated on first resize / camera

        self._apply_palette()
        self._build_ui()

        # Batch-flush log lines at ~25 fps — never blocks the event loop
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(40)
        self._flush_timer.timeout.connect(self._flush_log)
        self._flush_timer.start()

        if not os.path.exists(DISCOVER_PY):
            self._q(f'[WARN] script not found: {DISCOVER_PY}')
            self._q('       Put topsee_udp_discover.py in the same directory.')
        elif os.geteuid() != 0:
            self._q('[WARN] Not running as root.')
            self._q('       UDP discovery needs sudo to bind port 3001.')
            self._q('       Run:  sudo python3 topsee_gui.py')
            self._status('Run with sudo for discovery', '#c07050')
        else:
            QTimer.singleShot(200, self._start)

    # ── palette ───────────────────────────────────────────────────────────────
    def _apply_palette(self):
        p = QPalette()
        p.setColor(QPalette.ColorRole.Window,           QColor('#11131a'))
        p.setColor(QPalette.ColorRole.WindowText,       QColor('#c0c4d0'))
        p.setColor(QPalette.ColorRole.Base,             QColor('#181b22'))
        p.setColor(QPalette.ColorRole.Text,             QColor('#c0c4d0'))
        p.setColor(QPalette.ColorRole.Button,           QColor('#202430'))
        p.setColor(QPalette.ColorRole.ButtonText,       QColor('#c0c4d0'))
        p.setColor(QPalette.ColorRole.Highlight,        QColor('#285070'))
        p.setColor(QPalette.ColorRole.HighlightedText,  QColor('#ffffff'))
        QApplication.instance().setPalette(p)

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        root = QVBoxLayout(cw)
        root.setContentsMargins(10, 8, 10, 6)
        root.setSpacing(6)

        # header bar
        bar = QHBoxLayout(); bar.setSpacing(8)
        title = QLabel('Topsee / Tianshitong · Camera Discovery')
        title.setFont(QFont('Monospace', 11))
        title.setStyleSheet('color:#6aafd4; font-weight:bold;')
        bar.addWidget(title); bar.addStretch()

        self.btn_scan = QPushButton('⟳  Scan')
        self.btn_scan.setFixedHeight(30)
        self.btn_scan.setMinimumWidth(90)
        self.btn_scan.setStyleSheet(_btn('#285070', '#386080'))
        self.btn_scan.clicked.connect(self._start)
        bar.addWidget(self.btn_scan)

        btn_ref = QPushButton('↺  Refresh snapshots')
        btn_ref.setFixedHeight(30)
        btn_ref.setMinimumWidth(150)
        btn_ref.setStyleSheet(_btn('#252830', '#303540'))
        btn_ref.clicked.connect(self._refresh_all)
        bar.addWidget(btn_ref)
        root.addLayout(bar)

        # splitter
        sp = QSplitter(ORIENT_V)
        sp.setHandleWidth(5)
        sp.setStyleSheet('QSplitter::handle{background:#252830;}'
                         'QSplitter::handle:hover{background:#4a85a8;}')

        # log — QPlainTextEdit is far faster than QTextEdit for streaming text
        self.log_w = QPlainTextEdit()
        self.log_w.setReadOnly(True)
        self.log_w.setFont(QFont('Monospace', 9))
        self.log_w.setMaximumBlockCount(4000)
        self.log_w.setStyleSheet("""
            QPlainTextEdit {
                background: #0b0d12;
                color: #88c890;
                border: 1px solid #252830;
                border-radius: 4px;
                padding: 4px 6px;
            }
        """)
        self.log_w.setMinimumHeight(100)
        sp.addWidget(self.log_w)

        # snapshot area
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet("""
            QScrollArea{border:1px solid #252830; border-radius:4px;
                        background:#11131a;}
            QScrollBar:vertical{background:#181b22; width:9px;}
            QScrollBar::handle:vertical{background:#2a2f3c;
                border-radius:4px; min-height:20px;}
            QScrollBar::handle:vertical:hover{background:#4a85a8;}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical{height:0;}
        """)
        grid_w = QWidget()
        grid_w.setStyleSheet('background:#11131a;')
        self.grid = QGridLayout(grid_w)
        self.grid.setContentsMargins(10, 10, 10, 10)
        self.grid.setSpacing(10)
        self.grid.setColumnStretch(self._cur_cols, 1)
        self.grid.setRowStretch(999, 1)

        self._ph = QLabel('No cameras yet')
        self._ph.setAlignment(ALIGN_CENTER)
        self._ph.setFont(QFont('Monospace', 10))
        self._ph.setStyleSheet('color:#2a2f3c;')
        self.grid.addWidget(self._ph, 0, 0, 1, self._cur_cols)

        self._scroll.setWidget(grid_w)
        sp.addWidget(self._scroll)
        sp.setSizes([220, 580])
        root.addWidget(sp, 1)

        self._stlbl = QLabel('Ready')
        self._stlbl.setFont(QFont('Monospace', 8))
        self._stlbl.setStyleSheet('color:#333; padding:1px 4px;')
        root.addWidget(self._stlbl)

    # ── discovery ─────────────────────────────────────────────────────────────
    def _start(self):
        if self._worker and self._worker.isRunning():
            return
        self._clear_grid()
        self.log_w.clear()
        self._log_queue.clear()
        self._q('[*] Starting discovery…')
        self._status('Scanning…', '#6aafd4')
        self.btn_scan.setEnabled(False)

        self._worker = DiscoverWorker(DISCOVER_PY)
        # Signal is cross-thread safe; we push to deque, never touch widget
        self._worker.line.connect(self._q)
        self._worker.camera.connect(self._on_camera)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _cols(self):
        """How many tile columns fit in the current scroll-area width."""
        # scroll area is the second widget in the splitter
        avail = self._scroll.viewport().width() - 20   # subtract margins
        cols  = max(1, avail // (TILE_W + 10))
        return cols

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Reflow grid if column count changed
        new_cols = self._cols()
        if new_cols != self._cur_cols and self._tiles:
            self._cur_cols = new_cols
            self._reflow()

    def _reflow(self):
        """Pull all tiles out of the grid and reinsert with current column count."""
        ordered = list(self._tiles.values())   # insertion order (Python 3.7+)
        for tile in ordered:
            self.grid.removeWidget(tile)
        # clear leftover stretches and re-add
        self.grid.setColumnStretch(self._cur_cols, 1)
        for pos, tile in enumerate(ordered):
            row, col = divmod(pos, self._cur_cols)
            self.grid.addWidget(tile, row, col)
        self._tile_pos = len(ordered)

    def _on_camera(self, ip, url, rtsp_url):
        if ip in self._tiles:
            return
        if self._tile_pos == 0:
            self._ph.setParent(None)
        tile = CameraTile(ip, url, rtsp_url)
        col_count = self._cols()
        self._cur_cols = col_count
        row, col = divmod(self._tile_pos, col_count)
        self.grid.addWidget(tile, row, col)
        self._tiles[ip] = tile
        self._tile_pos += 1
        self._status(f'{len(self._tiles)} camera(s) found', '#6aafd4')

    def _on_done(self, code):
        self.btn_scan.setEnabled(True)
        n = len(self._tiles)
        if code == 0:
            self._status(f'Done — {n} camera(s) found',
                         '#6aafd4' if n else '#555')
        else:
            self._status(f'Scan ended (exit {code})', '#c07050')
            if n == 0:
                self._q(f'[HINT] exit {code} — running as root?')
        if n == 0 and self._tile_pos == 0:
            self._ph.setText('No cameras found')
            self.grid.addWidget(self._ph, 0, 0, 1, self._cur_cols)

    # ── log ───────────────────────────────────────────────────────────────────
    def _q(self, line: str):
        """Thread-safe: push to deque only, never touch Qt widgets."""
        self._log_queue.append(line)

    def _flush_log(self):
        """Main-thread timer: drain deque and append to widget in one shot."""
        if not self._log_queue:
            return
        lines = []
        while self._log_queue:
            lines.append(self._log_queue.popleft())
        self.log_w.appendPlainText('\n'.join(lines))
        sb = self.log_w.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _status(self, msg, color='#444'):
        self._stlbl.setText(msg)
        self._stlbl.setStyleSheet(f'color:{color}; padding:1px 4px;')

    # ── grid ──────────────────────────────────────────────────────────────────
    def _refresh_all(self):
        for t in self._tiles.values():
            t.refresh()
        self._status('Refreshing snapshots…', '#6aafd4')

    def _clear_grid(self):
        for t in self._tiles.values():
            t.setParent(None); t.deleteLater()
        self._tiles.clear()
        self._tile_pos = 0
        self._cur_cols = self._cols()
        self._ph.setText('Scanning…')
        self.grid.addWidget(self._ph, 0, 0, 1, self._cur_cols)


# ── button style helper ───────────────────────────────────────────────────────
def _btn(bg, hover):
    return (f'QPushButton{{background:{bg}; color:#b8bcc8;'
            f' border:1px solid #353a48; border-radius:4px;'
            f' padding:3px 14px; font-family:Monospace; font-size:9pt;}}'
            f'QPushButton:hover{{background:{hover}; border-color:#4a85a8;}}'
            f'QPushButton:pressed{{background:#182838;}}'
            f'QPushButton:disabled{{background:#181b22; color:#383c48;}}')


# ── entry ─────────────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Topsee Camera Discovery')
    app.setStyle('Fusion')
    win = MainWindow()
    win.show()
    try:
        sys.exit(app.exec())
    except TypeError:
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()

