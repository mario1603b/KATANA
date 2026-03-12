"""
KATANA v7.0  ·  Threat Intelligence Platform
Sophos Firewall Log Analyzer
─────────────────────────────────────────────
Estética: Minimalismo editorial
Paleta:   Blanco hueso · Grafito · Azul acento
"""

import sys, os, re, time, json, traceback, webbrowser, warnings
import urllib3
from datetime import datetime

import requests
from fpdf import FPDF

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFileDialog, QMessageBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit, QComboBox,
    QFrame, QHeaderView, QProgressBar, QSplitter, QCheckBox,
    QGroupBox, QScrollArea, QAbstractItemView, QSpinBox,
    QDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem,
    QSizePolicy, QMenu, QStackedWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import (
    QFont, QColor, QCursor, QBrush, QAction, QPixmap, QPainter,
    QLinearGradient, QPen, QFontDatabase
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─────────────────────────────────────────────
#  TOKENS DE DISEÑO — TEMAS
# ─────────────────────────────────────────────
MONO = "'IBM Plex Mono', 'Consolas', 'Courier New', monospace"
SANS = "'IBM Plex Sans', 'Segoe UI', 'Helvetica Neue', sans-serif"

THEMES = {
    "light": {
        "BG":      "#F7F7F5",
        "SURFACE": "#FFFFFF",
        "BORDER":  "#E2E2DF",
        "BORDER2": "#CBCBC6",
        "INK":     "#111111",
        "INK2":    "#555550",
        "INK_DIM": "#999993",
        "ACCENT":  "#1A6BFF",
        "ACCENT_D":"#0F4FCC",
        "DANGER":  "#D93025",
        "SUCCESS": "#1D7A46",
        "WARN":    "#B45309",
        "S_CRIT":  "#C41B0E",
        "S_HIGH":  "#B45309",
        "S_MED":   "#1A6BFF",
        "S_LOW":   "#1D7A46",
        "CONSOLE_BG":  "#111111",
        "CONSOLE_FG":  "#A8FFB0",
    },
    "dark": {
        "BG":      "#0E0E11",
        "SURFACE": "#16161A",
        "BORDER":  "#232328",
        "BORDER2": "#323238",
        "INK":     "#EEEEF0",
        "INK2":    "#9898A0",
        "INK_DIM": "#55555D",
        "ACCENT":  "#4D9FFF",
        "ACCENT_D":"#3080E8",
        "DANGER":  "#FF5549",
        "SUCCESS": "#34C969",
        "WARN":    "#F5A623",
        "S_CRIT":  "#FF5549",
        "S_HIGH":  "#F5A623",
        "S_MED":   "#4D9FFF",
        "S_LOW":   "#34C969",
        "CONSOLE_BG":  "#0A0A0D",
        "CONSOLE_FG":  "#A8FFB0",
    }
}

# Variables globales activas (se reasignan al cambiar tema)
_T = THEMES["light"]

# Acceso siempre-actualizado — usar T("KEY") en todo el codigo
def T(k): return _T[k]

SEV_COLOR = {"CRITICAL": "#C41B0E", "HIGH": "#B45309",
             "MEDIUM": "#1A6BFF", "LOW": "#1D7A46"}

def _update_sev_colors():
    global SEV_COLOR
    SEV_COLOR = {
        "CRITICAL": _T["S_CRIT"], "HIGH": _T["S_HIGH"],
        "MEDIUM":   _T["S_MED"],  "LOW":  _T["S_LOW"],
    }

def _build_qss():
    t = _T
    return f"""
* {{
    font-family: {SANS};
    font-size: 12px;
    color: {t['INK']};
}}
QMainWindow, QDialog {{
    background: {t['BG']};
}}
QWidget {{
    background: transparent;
}}
#sidebar {{
    background: {t['SURFACE']};
    border-right: 1px solid {t['BORDER']};
}}
#topbar {{
    background: {t['SURFACE']};
    border-bottom: 1px solid {t['BORDER']};
}}
#card {{
    background: {t['SURFACE']};
    border: 1px solid {t['BORDER']};
    border-radius: 4px;
}}
QPushButton {{
    background: transparent;
    color: {t['INK2']};
    border: 1px solid {t['BORDER2']};
    border-radius: 3px;
    padding: 6px 14px;
    font-size: 11px;
    text-align: left;
}}
QPushButton:hover {{
    background: {t['BG']};
    color: {t['INK']};
    border-color: {t['INK2']};
}}
QPushButton:pressed {{ background: {t['BORDER']}; }}
QPushButton:disabled {{ color: {t['INK_DIM']}; border-color: {t['BORDER']}; background: transparent; }}
QPushButton#primary {{
    background: {t['ACCENT']}; color: white; border: none; font-weight: 600;
}}
QPushButton#primary:hover {{ background: {t['ACCENT_D']}; }}
QPushButton#primary:disabled {{ background: {t['BORDER']}; color: {t['INK_DIM']}; }}
QPushButton#ghost {{
    background: transparent; border: none;
    color: {t['INK2']}; padding: 4px 8px; text-align: center;
}}
QPushButton#ghost:hover {{ color: {t['ACCENT']}; background: transparent; }}
QPushButton#danger {{
    background: transparent; color: {t['DANGER']}; border: 1px solid {t['DANGER']}55;
}}
QPushButton#danger:hover {{ background: {t['DANGER']}12; border-color: {t['DANGER']}; }}
QPushButton#danger:disabled {{ color: {t['INK_DIM']}; border-color: {t['BORDER']}; }}
QPushButton#success {{
    background: transparent; color: {t['SUCCESS']}; border: 1px solid {t['SUCCESS']}55;
}}
QPushButton#success:hover {{ background: {t['SUCCESS']}12; border-color: {t['SUCCESS']}; }}
QPushButton#success:disabled {{ color: {t['INK_DIM']}; border-color: {t['BORDER']}; }}
QPushButton#theme_btn {{
    background: transparent; border: 1px solid {t['BORDER2']};
    color: {t['INK2']}; padding: 4px 10px; text-align: center;
    border-radius: 12px; font-size: 10px;
}}
QPushButton#theme_btn:hover {{ color: {t['INK']}; border-color: {t['INK_DIM']}; }}
QTabWidget::pane {{
    background: {t['SURFACE']};
    border: 1px solid {t['BORDER']};
    border-top: none;
    border-radius: 0 0 4px 4px;
}}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent; color: {t['INK_DIM']};
    padding: 8px 20px; border: none;
    border-bottom: 2px solid transparent;
    font-size: 11px; font-weight: 500; margin-right: 2px;
}}
QTabBar::tab:selected {{ color: {t['INK']}; border-bottom: 2px solid {t['ACCENT']}; }}
QTabBar::tab:hover:!selected {{ color: {t['INK2']}; border-bottom: 2px solid {t['BORDER2']}; }}
QTreeWidget, QTableWidget {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: none; alternate-background-color: {t['BG']};
    gridline-color: {t['BORDER']};
    font-family: {MONO}; font-size: 11px; outline: none;
    selection-background-color: {t['ACCENT']}18; selection-color: {t['INK']};
}}
QTreeWidget::item, QTableWidget::item {{
    padding: 5px 10px; border-bottom: 1px solid {t['BORDER']};
}}
QTreeWidget::item:selected, QTableWidget::item:selected {{
    background: {t['ACCENT']}15; color: {t['INK']};
    border-left: 2px solid {t['ACCENT']};
}}
QTreeWidget::item:hover:!selected, QTableWidget::item:hover:!selected {{
    background: {t['BG']};
}}
QHeaderView::section {{
    background: {t['BG']}; color: {t['INK_DIM']};
    border: none; border-bottom: 1px solid {t['BORDER2']};
    border-right: 1px solid {t['BORDER']};
    padding: 6px 10px; font-size: 10px; font-weight: 600;
    letter-spacing: 0.8px; font-family: {SANS};
}}
QLineEdit {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: 1px solid {t['BORDER2']}; border-radius: 3px;
    padding: 6px 10px; font-size: 12px;
    selection-background-color: {t['ACCENT']}33;
}}
QLineEdit:focus {{ border-color: {t['ACCENT']}; }}
QComboBox {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: 1px solid {t['BORDER2']}; border-radius: 3px;
    padding: 5px 10px; font-size: 11px; min-width: 100px;
}}
QComboBox:focus {{ border-color: {t['ACCENT']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: 1px solid {t['BORDER2']};
    selection-background-color: {t['ACCENT']}18; selection-color: {t['INK']}; outline: none;
}}
QTextEdit#console {{
    background: {t['CONSOLE_BG']}; color: {t['CONSOLE_FG']};
    border: none; border-radius: 3px;
    font-family: {MONO}; font-size: 11px; padding: 10px;
}}
QTextEdit {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: 1px solid {t['BORDER']}; border-radius: 3px; padding: 6px;
}}
QCheckBox {{ color: {t['INK2']}; spacing: 6px; font-size: 11px; }}
QCheckBox::indicator {{
    width: 13px; height: 13px;
    background: {t['SURFACE']}; border: 1px solid {t['BORDER2']}; border-radius: 2px;
}}
QCheckBox::indicator:checked {{ background: {t['ACCENT']}; border-color: {t['ACCENT']}; }}
QProgressBar {{
    background: {t['BORDER']}; border: none; border-radius: 1px; height: 2px; color: transparent;
}}
QProgressBar::chunk {{ background: {t['ACCENT']}; border-radius: 1px; }}
QScrollBar:vertical {{ background: transparent; width: 5px; border: none; }}
QScrollBar::handle:vertical {{ background: {t['BORDER2']}; border-radius: 2px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {t['INK_DIM']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 5px; border: none; }}
QScrollBar::handle:horizontal {{ background: {t['BORDER2']}; border-radius: 2px; }}
QScrollBar::handle:horizontal:hover {{ background: {t['INK_DIM']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {t['BORDER']}; background: {t['BORDER']}; max-height: 1px;
}}
QSpinBox {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: 1px solid {t['BORDER2']}; border-radius: 3px; padding: 5px 8px;
}}
QSpinBox:focus {{ border-color: {t['ACCENT']}; }}
QGroupBox {{
    color: {t['INK_DIM']}; border: 1px solid {t['BORDER']};
    border-radius: 4px; margin-top: 12px; padding-top: 10px;
    font-size: 10px; font-weight: 600; letter-spacing: 0.8px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px; color: {t['INK_DIM']}; }}
QMenu {{
    background: {t['SURFACE']}; color: {t['INK']};
    border: 1px solid {t['BORDER2']}; padding: 4px; border-radius: 4px;
}}
QMenu::item {{ padding: 6px 18px; font-size: 12px; border-radius: 2px; }}
QMenu::item:selected {{ background: {t['ACCENT']}15; color: {t['INK']}; }}
QMenu::separator {{ height: 1px; background: {t['BORDER']}; margin: 4px 0; }}
QMessageBox {{ background: {t['SURFACE']}; }}
QMessageBox QLabel {{ color: {t['INK']}; font-size: 12px; }}
"""

# QSS inicial (modo claro)
QSS = _build_qss()

# ─────────────────────────────────────────────
#  HELPERS GLOBALES
# ─────────────────────────────────────────────
def sep(vertical=False):
    f = QFrame()
    f.setFrameShape(QFrame.Shape.VLine if vertical else QFrame.Shape.HLine)
    f.setFixedWidth(1) if vertical else f.setFixedHeight(1)
    f.setStyleSheet(f"background:{_T['BORDER']}; border:none;")
    return f

def lbl(text, size=12, color=None, bold=False, mono=False, dim=False):
    l = QLabel(text)
    family = MONO if mono else SANS
    weight = "600" if bold else "400"
    c = _T["INK_DIM"] if dim else (color or _T["INK"])
    l.setStyleSheet(f"font-family:{family}; font-size:{size}px;"
                    f"font-weight:{weight}; color:{c}; background:transparent;")
    return l

def spacer(h=None, v=None):
    w = QWidget()
    if h: w.setFixedWidth(h)
    if v: w.setFixedHeight(v)
    w.setSizePolicy(
        QSizePolicy.Policy.Expanding if not h else QSizePolicy.Policy.Fixed,
        QSizePolicy.Policy.Expanding if not v else QSizePolicy.Policy.Fixed
    )
    return w

# ─────────────────────────────────────────────
#  WORKERS
# ─────────────────────────────────────────────
class AnalysisWorker(QThread):
    progress_btn = pyqtSignal(str)
    log          = pyqtSignal(str)
    finished     = pyqtSignal(object, object, int, int)
    error        = pyqtSignal(str)

    def __init__(self, archivo, whitelist=None):
        super().__init__()
        self.archivo   = archivo
        self.whitelist = set(whitelist or [])

    def run(self):
        try:
            import pandas as pd
            self.log.emit(f"Loading  {os.path.basename(self.archivo)}")
            try:
                df = pd.read_csv(self.archivo, sep=None, engine='python')
            except Exception:
                df = pd.read_csv(self.archivo, sep=',')

            self.log.emit(f"{len(df)} rows · {len(df.columns)} columns")
            df.columns = df.columns.str.strip()
            df['_row'] = df.fillna('').astype(str).apply(lambda r: ' '.join(r), axis=1)

            ip_col = next((c for c in df.columns if re.search(
                r'src|source|attacker|client|remote', c, re.I)), None)
            if ip_col:
                self.log.emit(f"IP column  →  '{ip_col}'")
                df['IP_Atacante'] = df[ip_col].astype(str).str.extract(
                    r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
            else:
                df['IP_Atacante'] = df['_row'].str.extract(
                    r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

            df_ips = df.dropna(subset=['IP_Atacante']).copy()
            priv = re.compile(
                r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)')
            df_ips = df_ips[~df_ips['IP_Atacante'].str.match(priv)]
            if self.whitelist:
                df_ips = df_ips[~df_ips['IP_Atacante'].isin(self.whitelist)]
            if df_ips.empty:
                self.error.emit("No external attacker IPs found in this log."); return

            # Usuario
            df_ips['Usuario'] = df_ips['_row'].str.extract(
                r"User\s+([^\s]+)\s+failed\s+to\s+login", flags=re.I)
            if 'Username' in df_ips.columns:
                df_ips['Usuario'] = df_ips['Usuario'].combine_first(df_ips['Username'])
            df_ips['Usuario'] = df_ips['Usuario'].fillna('—').replace(
                {'': '—', 'nan': '—', 'N/A': '—'})

            # Puerto
            pc = next((c for c in df_ips.columns if re.search(
                r'dst.?port|dport|dest.?port', c, re.I)), None)
            df_ips['Puerto'] = (df_ips[pc].astype(str) if pc else
                                df_ips['_row'].str.extract(
                                    r"(?:dst|dport)[\s:=]+(\d{1,5})", flags=re.I))
            df_ips['Puerto'] = df_ips['Puerto'].fillna('—')

            # Timestamp
            tc = next((c for c in df_ips.columns if re.search(
                r'^(time|date|timestamp|fecha)$', c, re.I)), None)
            if tc:
                df_ips['Timestamp'] = pd.to_datetime(df_ips[tc], errors='coerce')
            else:
                df_ips['Timestamp'] = pd.NaT

            # Geolocalización
            ips_u = df_ips['IP_Atacante'].unique().tolist()
            total = len(ips_u)
            paises = {}; lats = {}; lons = {}

            self.log.emit(f"Geolocating  {total} unique IPs")
            for i in range(0, total, 100):
                batch = ips_u[i:i+100]
                self.progress_btn.emit(
                    f"Geolocating  {min(i+100,total)} / {total}")
                try:
                    r = requests.post("http://ip-api.com/batch",
                        json=[{"query": ip, "fields": "country,lat,lon,status"}
                              for ip in batch], timeout=12)
                    if r.status_code == 200:
                        for ip, d in zip(batch, r.json()):
                            paises[ip] = d.get('country','Unknown') \
                                if d.get('status')=='success' else 'Unknown'
                            lats[ip]   = d.get('lat', 0.0)
                            lons[ip]   = d.get('lon', 0.0)
                    else:
                        for ip in batch: paises[ip]='Unknown'; lats[ip]=0.; lons[ip]=0.
                except Exception:
                    for ip in batch: paises[ip]='Error'; lats[ip]=0.; lons[ip]=0.
                time.sleep(1.2)

            df_ips['Pais'] = df_ips['IP_Atacante'].map(paises)
            df_ips['Lat']  = df_ips['IP_Atacante'].map(lats)
            df_ips['Lon']  = df_ips['IP_Atacante'].map(lons)
            df_mapa = df_ips.groupby('Pais').size().reset_index(name='Total_Ataques')

            # Severidad
            cnt = df_ips['IP_Atacante'].value_counts(); mx = cnt.max() or 1
            def sev(c):
                r = c/mx
                if r > .5:  return "CRITICAL"
                if r > .25: return "HIGH"
                if r > .1:  return "MEDIUM"
                return "LOW"
            df_ips['Severidad'] = df_ips['IP_Atacante'].map(lambda ip: sev(cnt.get(ip,1)))

            # Export CSV
            cols = [c for c in ['Timestamp','IP_Atacante','Pais','Puerto',
                                 'Usuario','Severidad','Lat','Lon']
                    if c in df_ips.columns]
            df_ips[cols].to_csv('Resultado_KATANA.csv', index=False)
            self.log.emit("Exported  Resultado_KATANA.csv")
            self.finished.emit(df_ips, df_mapa, total, len(df_ips))

        except Exception as e:
            traceback.print_exc(); self.error.emit(str(e))


class AegisWorker(QThread):
    log      = pyqtSignal(str)
    finished = pyqtSignal(int, int)

    def __init__(self, fw_ip, fw_port, fw_user, fw_pass, ips, dry=False):
        super().__init__()
        self.fw_ip=fw_ip; self.fw_port=fw_port; self.fw_user=fw_user
        self.fw_pass=fw_pass; self.ips=ips; self.dry=dry

    def run(self):
        if self.dry:
            self.log.emit("DRY RUN — no requests sent")
            for ip in self.ips:
                self.log.emit(f"  sim  AEGIS_{ip.replace('.','_')}"); time.sleep(0.05)
            self.log.emit(f"Done  {len(self.ips)} objects simulated")
            self.finished.emit(len(self.ips), len(self.ips)); return

        url = f"https://{self.fw_ip}:{self.fw_port}/webconsole/APIController"
        ok = 0; created = []
        for ip in self.ips:
            name = f"AEGIS_{ip.replace('.','_')}"
            xml  = (f"<Request><Login><Username>{self.fw_user}</Username>"
                    f"<Password>{self.fw_pass}</Password></Login>"
                    f"<Set><IPHost><n>{name}</n><IPFamily>IPv4</IPFamily>"
                    f"<HostType>IP</HostType><IPAddress>{ip}</IPAddress>"
                    f"</IPHost></Set></Request>")
            self.log.emit(f"  →  {name}")
            try:
                res = requests.post(url, data={'reqxml': xml}, verify=False, timeout=5)
                if 'status="200"' in res.text or 'Configuration applied' in res.text:
                    self.log.emit("     ok"); ok += 1; created.append(name)
                elif 'already exists' in res.text:
                    self.log.emit("     exists"); created.append(name)
                elif 'Authentication Failure' in res.text:
                    self.log.emit("     auth error"); break
                else:
                    self.log.emit("     unexpected response")
            except Exception:
                self.log.emit("     connection error"); break
            time.sleep(0.5)

        if created:
            self.log.emit("Updating group  KATANA_BLACKLIST")
            hosts = "".join([f"<Host>{h}</Host>" for h in created])
            xml_g = (f"<Request><Login><Username>{self.fw_user}</Username>"
                     f"<Password>{self.fw_pass}</Password></Login>"
                     f"<Set><IPHostGroup><n>KATANA_BLACKLIST</n>"
                     f"<IPFamily>IPv4</IPFamily><HostList>{hosts}</HostList>"
                     f"</IPHostGroup></Set></Request>")
            try:
                r = requests.post(url, data={'reqxml': xml_g}, verify=False, timeout=10)
                self.log.emit("     ok" if 'status="200"' in r.text or
                              'Configuration applied' in r.text else "     group error")
            except Exception:
                self.log.emit("     group connection error")
        self.finished.emit(ok, len(self.ips))


# ─────────────────────────────────────────────
#  COMPONENTES
# ─────────────────────────────────────────────
class MetricTile(QWidget):
    """Tarjeta de métrica minimalista"""
    def __init__(self, title, accent=ACCENT):
        super().__init__()
        self.accent = accent
        self.setObjectName("card")
        lo = QVBoxLayout(self); lo.setContentsMargins(16,12,16,12); lo.setSpacing(4)
        self._val = lbl("—", size=26, color=accent, bold=True, mono=True)
        lo.addWidget(self._val)
        lo.addWidget(lbl(title, size=10, dim=True))
        self.setMinimumWidth(100)

    def set(self, v): self._val.setText(str(v))


class StatusDot(QWidget):
    """Indicador de estado circular"""
    def __init__(self, color=None, size=7):
        super().__init__()
        self._c = color or T("SUCCESS"); self._s = size
        self.setFixedSize(size+2, size+2)

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(self._c))); p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(1, 1, self._s, self._s)


class FilterRow(QWidget):
    changed = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        lo = QHBoxLayout(self); lo.setContentsMargins(10,6,10,6); lo.setSpacing(8)
        lo.addWidget(lbl("Filter:", size=10, dim=True))

        self.ip   = QLineEdit(); self.ip.setPlaceholderText("IP or range")
        self.ip.setFixedWidth(150); self.ip.textChanged.connect(self._emit)

        self.country = QLineEdit(); self.country.setPlaceholderText("Country")
        self.country.setFixedWidth(110); self.country.textChanged.connect(self._emit)

        self.sev = QComboBox()
        self.sev.addItems(["All","CRITICAL","HIGH","MEDIUM","LOW"])
        self.sev.setFixedWidth(100); self.sev.currentTextChanged.connect(self._emit)

        clr = QPushButton("Clear"); clr.setObjectName("ghost")
        clr.setFixedWidth(50); clr.clicked.connect(self._clear)

        for w in [self.ip, self.country, self.sev, clr]: lo.addWidget(w)
        lo.addStretch()

    def _emit(self):
        self.changed.emit(self.ip.text(), self.country.text(), self.sev.currentText())

    def _clear(self):
        self.ip.clear(); self.country.clear(); self.sev.setCurrentIndex(0)


# ─────────────────────────────────────────────
#  PDF
# ─────────────────────────────────────────────
def _build_pdf(df, df_mapa, path):
    pdf = FPDF(); pdf.add_page()

    # Header
    pdf.set_font("Arial",'B',18)
    pdf.set_text_color(26,107,255)
    pdf.cell(0,12,"KATANA v7.0 — Executive Forensic Report",ln=True,align='C')
    pdf.set_font("Arial",'',9); pdf.set_text_color(80,80,80)
    pdf.cell(0,7,f"Generated  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}   |   "
                 f"{len(df)} events analyzed",ln=True,align='C')
    pdf.ln(6)

    def section(title):
        pdf.set_font("Arial",'B',12); pdf.set_text_color(17,17,17)
        pdf.cell(0,9,title,ln=True)
        pdf.set_draw_color(200,200,195); pdf.line(10,pdf.get_y(),200,pdf.get_y()); pdf.ln(3)

    def row(label, value):
        pdf.set_font("Arial",'',11); pdf.set_text_color(85,85,80)
        pdf.cell(90,8,f"  {label}",border=0)
        pdf.set_font("Arial",'B',11); pdf.set_text_color(17,17,17)
        pdf.cell(0,8,str(value),ln=True)
        pdf.set_font("Arial",'',11)

    def table_header(*cols_widths):
        pdf.set_font("Arial",'B',9); pdf.set_text_color(100,100,100)
        for col, w in cols_widths: pdf.cell(w,7,col,border=1)
        pdf.ln()

    def table_row(*vals_widths):
        pdf.set_font("Arial",'',10); pdf.set_text_color(17,17,17)
        for v, w in vals_widths: pdf.cell(w,7,str(v),border=1)
        pdf.ln()

    # Summary
    section("1.  INCIDENT SUMMARY")
    crit = df[df['Severidad']=='CRITICAL']['IP_Atacante'].nunique() \
           if 'Severidad' in df.columns else '—'
    for k,v in [("Total events",len(df)),("Unique attacker IPs",df['IP_Atacante'].nunique()),
                ("Countries of origin",df['Pais'].nunique()),("CRITICAL severity IPs",crit)]:
        row(k, v)
    pdf.ln(4)

    # Top countries
    section("2.  TOP 10 ATTACK ORIGINS")
    table_header(("COUNTRY",95),("EVENTS",50),("% TOTAL",45))
    for c,n in df['Pais'].value_counts().head(10).items():
        table_row((c,95),(n,50),(f"{n/len(df)*100:.1f}%",45))
    pdf.ln(4)

    # Top IPs
    section("3.  TOP 15 IPs FOR BLACKLISTING")
    table_header(("IP ADDRESS",60),("COUNTRY",65),("EVENTS",35),("SEVERITY",30))
    top = df.groupby(['IP_Atacante','Pais']).size().reset_index(name='N')
    if 'Severidad' in df.columns:
        sm = df[['IP_Atacante','Severidad']].drop_duplicates().set_index('IP_Atacante')['Severidad']
        top['S'] = top['IP_Atacante'].map(sm).fillna('—')
    else:
        top['S'] = '—'
    for _,r in top.sort_values('N',ascending=False).head(15).iterrows():
        table_row((r['IP_Atacante'],60),(str(r['Pais'])[:20],65),(r['N'],35),(r['S'],30))
    pdf.ln(4)

    # Users
    if 'Usuario' in df.columns:
        uu = df[df['Usuario']!='—']['Usuario'].value_counts().head(10)
        if not uu.empty:
            pdf.add_page()
            section("4.  TARGETED ACCOUNTS (BRUTE FORCE)")
            table_header(("USERNAME",130),("ATTEMPTS",60))
            for u,n in uu.items(): table_row((u,130),(n,60))

    # Footer
    pdf.set_y(-14); pdf.set_font("Arial",'I',8); pdf.set_text_color(150,150,145)
    pdf.cell(0,8,"KATANA v7.0  ·  Confidential  ·  Internal use only",align='C')
    pdf.output(path)


# ─────────────────────────────────────────────
#  DIÁLOGOS
# ─────────────────────────────────────────────
class ExportDialog(QDialog):
    def __init__(self, df, df_mapa, parent=None):
        super().__init__(parent)
        self.df=df; self.df_mapa=df_mapa
        self.setWindowTitle("Export Data"); self.setFixedWidth(400)
        lo = QVBoxLayout(self); lo.setContentsMargins(24,24,24,20); lo.setSpacing(12)

        lo.addWidget(lbl("Export", size=15, bold=True))
        lo.addWidget(sep())

        self.chk_pdf  = QCheckBox("PDF Report  (executive summary)"); self.chk_pdf.setChecked(True)
        self.chk_xlsx = QCheckBox("Excel  (.xlsx)  — full IP table")
        self.chk_json = QCheckBox("JSON  — structured data for SIEM / SOAR")
        self.chk_ioc  = QCheckBox("IOC List  (.txt)  — plain IP list")
        for c in [self.chk_pdf, self.chk_xlsx, self.chk_json, self.chk_ioc]: lo.addWidget(c)

        lo.addWidget(sep())

        row = QHBoxLayout(); row.setSpacing(6)
        self.chk_top = QCheckBox("Limit to top")
        self.spin    = QSpinBox(); self.spin.setRange(10,9999); self.spin.setValue(100)
        self.spin.setFixedWidth(70)
        row.addWidget(self.chk_top); row.addWidget(self.spin)
        row.addWidget(lbl("IPs", dim=True)); row.addStretch()
        lo.addLayout(row)

        lo.addWidget(sep())
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setObjectName("primary")
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Export")
        btns.accepted.connect(self._run); btns.rejected.connect(self.reject)
        lo.addWidget(btns)

    def _run(self):
        df = self.df
        if self.chk_top.isChecked():
            top_ips = df['IP_Atacante'].value_counts().head(self.spin.value()).index
            df = df[df['IP_Atacante'].isin(top_ips)]

        ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
        out = []

        if self.chk_pdf.isChecked():
            p = f"KATANA_Report_{ts}.pdf"; _build_pdf(df, self.df_mapa, p); out.append(p)

        if self.chk_xlsx.isChecked():
            try:
                p = f"KATANA_IPs_{ts}.xlsx"
                df.drop(columns=['_row','Fila_Completa'], errors='ignore').to_excel(p, index=False)
                out.append(p)
            except Exception as e:
                out.append(f"xlsx error: {e}")

        if self.chk_json.isChecked():
            p = f"KATANA_SIEM_{ts}.json"
            c = df.groupby(['IP_Atacante','Pais','Severidad']).size().reset_index(name='events')
            payload = {"katana":"7.0","ts":ts,"total_ips":int(df['IP_Atacante'].nunique()),
                       "total_events":int(len(df)),"iocs":c.to_dict('records')}
            with open(p,'w',encoding='utf-8') as f: json.dump(payload,f,indent=2,ensure_ascii=False)
            out.append(p)

        if self.chk_ioc.isChecked():
            p = f"KATANA_IOC_{ts}.txt"
            ips = df['IP_Atacante'].value_counts().index.tolist()
            with open(p,'w') as f:
                f.write(f"# KATANA IOC  {datetime.now()}\n# {len(ips)} IPs\n\n")
                f.write("\n".join(ips))
            out.append(p)

        QMessageBox.information(self, "Done", "Files created:\n\n" + "\n".join(out))
        for o in out:
            if o.endswith('.pdf'):
                webbrowser.open(f"file://{os.path.abspath(o)}")
        self.accept()


class WhitelistDialog(QDialog):
    def __init__(self, whitelist, parent=None):
        super().__init__(parent)
        self._wl = whitelist
        self.setWindowTitle("IP Whitelist"); self.setMinimumSize(360, 380)
        lo = QVBoxLayout(self); lo.setContentsMargins(20,20,20,16); lo.setSpacing(10)
        lo.addWidget(lbl("IP Whitelist", size=14, bold=True))
        lo.addWidget(lbl("IPs excluded from analysis. One per line.", dim=True, size=11))
        lo.addWidget(sep())
        self.txt = QTextEdit(); self.txt.setFont(QFont("Consolas",11))
        self.txt.setPlaceholderText("192.168.1.1\n10.0.0.5")
        self.txt.setText("\n".join(sorted(whitelist)))
        lo.addWidget(self.txt,1)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Save).setObjectName("primary")
        btns.accepted.connect(self._save); btns.rejected.connect(self.reject)
        lo.addWidget(btns)

    def _save(self):
        self._wl.clear()
        self._wl.update({l.strip() for l in self.txt.toPlainText().splitlines() if l.strip()})
        self.accept()


# ─────────────────────────────────────────────
#  VENTANA PRINCIPAL
# ─────────────────────────────────────────────
class KatanaApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KATANA  ·  Threat Intelligence Platform")
        self.setMinimumSize(1300, 800)
        self.df     = None
        self.df_map = None
        self._wl    = set()
        self._hist  = []
        self._aw    = None   # analysis worker
        self._egw   = None   # aegis worker
        self._dark  = False  # tema oscuro
        self.setStyleSheet(QSS)
        self._ui()

    # ── Layout ───────────────────────────────
    def _ui(self):
        root = QWidget(); self.setCentralWidget(root)
        rl = QVBoxLayout(root); rl.setContentsMargins(0,0,0,0); rl.setSpacing(0)

        rl.addWidget(self._topbar())

        body = QWidget(); bl = QHBoxLayout(body)
        bl.setContentsMargins(0,0,0,0); bl.setSpacing(0)
        rl.addWidget(body, 1)

        bl.addWidget(self._sidebar())

        main = QWidget(); main.setStyleSheet(f"background:{T("BG")};")
        ml = QHBoxLayout(main); ml.setContentsMargins(16,16,16,16); ml.setSpacing(12)
        spl = QSplitter(Qt.Orientation.Horizontal)
        spl.setStyleSheet(f"QSplitter::handle{{background:{T("BORDER")};width:1px;}}")
        spl.addWidget(self._ip_panel())
        spl.addWidget(self._tabs())
        spl.setSizes([290, 880])
        ml.addWidget(spl)
        bl.addWidget(main, 1)

    # ── Topbar ───────────────────────────────
    def _topbar(self):
        bar = QWidget(); bar.setObjectName("topbar"); bar.setFixedHeight(38)
        lo = QHBoxLayout(bar); lo.setContentsMargins(20,0,20,0); lo.setSpacing(16)

        dot = StatusDot(T("SUCCESS"))
        lo.addWidget(dot)
        lo.addWidget(lbl("KATANA", size=13, bold=True, color=T("INK")))
        lo.addWidget(lbl("v7.0", size=11, dim=True))
        lo.addWidget(sep(vertical=True)); lo.addWidget(spacer(h=4))

        self._tb_file = lbl("No log loaded", size=10, dim=True)
        lo.addWidget(self._tb_file)
        lo.addWidget(spacer())

        self._tb_time = lbl("", size=10, mono=True, dim=True)
        lo.addWidget(self._tb_time)

        # Botón tema
        self._btn_theme = QPushButton("○  Light")
        self._btn_theme.setObjectName("theme_btn")
        self._btn_theme.setFixedSize(72, 24)
        self._btn_theme.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_theme.clicked.connect(self._toggle_theme)
        lo.addWidget(self._btn_theme)

        t = QTimer(self); t.timeout.connect(
            lambda: self._tb_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S")))
        t.start(1000); self._tb_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        return bar

    # ── Sidebar ──────────────────────────────
    def _sidebar(self):
        sb = QWidget(); sb.setObjectName("sidebar"); sb.setFixedWidth(210)
        lo = QVBoxLayout(sb); lo.setContentsMargins(16,20,16,16); lo.setSpacing(0)

        lo.addWidget(lbl("Operations", size=10, dim=True)); lo.addSpacing(8)

        self.btn_load = QPushButton("Load CSV log")
        self.btn_load.setFixedHeight(36)
        self.btn_load.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_load.clicked.connect(self._load)
        lo.addWidget(self.btn_load)

        self._file_lbl = lbl("No file selected", size=10, dim=True)
        self._file_lbl.setWordWrap(True); lo.addSpacing(6); lo.addWidget(self._file_lbl)

        lo.addSpacing(10)
        self._pbar = QProgressBar(); self._pbar.setFixedHeight(2)
        self._pbar.setRange(0,0); self._pbar.setVisible(False)
        lo.addWidget(self._pbar); lo.addSpacing(6)

        self.btn_run = QPushButton("Run analysis")
        self.btn_run.setObjectName("primary"); self.btn_run.setFixedHeight(38)
        self.btn_run.setEnabled(False)
        self.btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_run.clicked.connect(self._run)
        lo.addWidget(self.btn_run); lo.addSpacing(8)

        self.btn_export = QPushButton("Export data")
        self.btn_export.setObjectName("success"); self.btn_export.setFixedHeight(34)
        self.btn_export.setEnabled(False)
        self.btn_export.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_export.clicked.connect(self._export)
        lo.addWidget(self.btn_export)

        lo.addSpacing(20); lo.addWidget(sep()); lo.addSpacing(16)
        lo.addWidget(lbl("Configuration", size=10, dim=True)); lo.addSpacing(8)

        btn_wl = QPushButton("IP Whitelist")
        btn_wl.setFixedHeight(32)
        btn_wl.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_wl.clicked.connect(self._whitelist_dlg)
        lo.addWidget(btn_wl)

        lo.addSpacing(20); lo.addWidget(sep()); lo.addSpacing(16)
        lo.addWidget(lbl("Metrics", size=10, dim=True)); lo.addSpacing(8)

        self.m_ips    = MetricTile("Unique IPs",     T("ACCENT"))
        self.m_events = MetricTile("Total events",   T("DANGER"))
        self.m_ctrs   = MetricTile("Countries",      T("WARN"))
        self.m_crit   = MetricTile("Critical IPs",   T("S_CRIT"))

        for m in [self.m_ips, self.m_events, self.m_ctrs, self.m_crit]:
            lo.addWidget(m); lo.addSpacing(6)

        lo.addStretch()
        lo.addWidget(lbl("Sophos Firewall Log Analyzer", size=9, dim=True))
        return sb

    # ── IP Panel ─────────────────────────────
    def _ip_panel(self):
        panel = QWidget(); panel.setObjectName("card")
        lo = QVBoxLayout(panel); lo.setContentsMargins(0,0,0,0); lo.setSpacing(0)

        # Header
        hdr = QWidget(); hdr.setFixedHeight(44)
        hdr.setStyleSheet(f"background:{T("BG")}; border-bottom:1px solid {T("BORDER")};")
        hl = QHBoxLayout(hdr); hl.setContentsMargins(14,0,10,0)
        hl.addWidget(lbl("Detected IPs", size=11, bold=True))
        hl.addStretch()
        self._ip_count = lbl("0", size=11, mono=True, color=T("ACCENT"))
        hl.addWidget(self._ip_count)
        btn_ctx = QPushButton("···"); btn_ctx.setObjectName("ghost")
        btn_ctx.setFixedSize(28,28)
        btn_ctx.clicked.connect(self._ip_menu)
        hl.addWidget(btn_ctx)
        lo.addWidget(hdr)

        # Filter
        self._filter = FilterRow()
        self._filter.changed.connect(self._filter_table)
        lo.addWidget(self._filter)
        lo.addWidget(sep())

        # Tree
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Sev", "Country", "IP", "Attempts"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(False)
        self.tree.setSortingEnabled(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._row_menu)
        hv = self.tree.header()
        hv.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hv.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hv.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hv.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(0, 62)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(3, 68)
        lo.addWidget(self.tree, 1)
        return panel

    # ── Tabs ─────────────────────────────────
    def _tabs(self):
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"QTabWidget {{ background:{T("BG")}; }}")

        t_dash  = QWidget(); self.tabs.addTab(t_dash,  "Dashboard")
        t_geo   = QWidget(); self.tabs.addTab(t_geo,   "Geography")
        t_time  = QWidget(); self.tabs.addTab(t_time,  "Timeline")
        t_usr   = QWidget(); self.tabs.addTab(t_usr,   "Users")
        t_pat   = QWidget(); self.tabs.addTab(t_pat,   "Patterns")
        t_intel = QWidget(); self.tabs.addTab(t_intel, "Intel Map")
        t_aegis = QWidget(); self.tabs.addTab(t_aegis, "AEGIS")
        t_hist  = QWidget(); self.tabs.addTab(t_hist,  "History")

        self._build_dashboard(t_dash)
        self._build_geo(t_geo)
        self._build_timeline(t_time)
        self._build_users(t_usr)
        self._build_patterns(t_pat)
        self._build_intel(t_intel)
        self._build_aegis(t_aegis)
        self._build_history(t_hist)
        return self.tabs

    # ── Tab: Dashboard ───────────────────────
    def _build_dashboard(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(16)

        # KPI row
        kpi_row = QHBoxLayout(); kpi_row.setSpacing(10)
        self._kpi = {}
        for k, t, c in [("events","Events",T("DANGER")),("ips","Unique IPs",T("ACCENT")),
                         ("countries","Countries",T("WARN")),("critical","Critical",T("S_CRIT")),
                         ("users","Users targeted",T("INK2"))]:
            tile = MetricTile(t, c); self._kpi[k] = tile; kpi_row.addWidget(tile)
        lo.addLayout(kpi_row)

        # Charts row
        charts = QHBoxLayout(); charts.setSpacing(12)

        self._dash_left  = self._chart_panel("Top countries")
        self._dash_right = self._chart_panel("Severity breakdown")
        charts.addWidget(self._dash_left, 1)
        charts.addWidget(self._dash_right, 1)
        lo.addLayout(charts, 1)

        # Status bar
        self._dash_status = QLabel("Load a CSV log and run analysis to begin.")
        _s = _T['SURFACE']; _i = _T['INK2']; _b = _T['BORDER']
        self._dash_status.setStyleSheet(
            f"background:{_s}; color:{_i}; border:1px solid {_b};"
            f" border-radius:3px; padding:8px 14px; font-size:11px;"
        )
        lo.addWidget(self._dash_status)

    def _chart_panel(self, title):
        w = QWidget(); w.setObjectName("card")
        lo = QVBoxLayout(w); lo.setContentsMargins(14,12,14,12); lo.setSpacing(8)
        lo.addWidget(lbl(title, size=11, bold=True))
        inner = QWidget(); inner.setObjectName("_inner")
        il = QVBoxLayout(inner); il.setContentsMargins(0,0,0,0)
        pl = lbl("No data", dim=True, size=11)
        pl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        il.addWidget(pl)
        lo.addWidget(inner, 1)
        w._inner = inner; w._placeholder = pl
        return w

    # ── Tab: Geography ───────────────────────
    def _build_geo(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20)
        lo.addWidget(lbl("Geographic Distribution", size=13, bold=True))
        lo.addWidget(lbl("Top 15 countries by attack volume", dim=True, size=11))
        lo.addSpacing(10)
        self._geo_inner = QWidget()
        gl = QVBoxLayout(self._geo_inner); gl.setContentsMargins(0,0,0,0)
        self._geo_ph = lbl("Run analysis to see geographic distribution.",
                           dim=True, size=11)
        self._geo_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gl.addWidget(self._geo_ph)
        lo.addWidget(self._geo_inner, 1)

    # ── Tab: Timeline ────────────────────────
    def _build_timeline(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(12)
        row = QHBoxLayout()
        row.addWidget(lbl("Attack Timeline", size=13, bold=True)); row.addStretch()
        row.addWidget(lbl("Granularity:", size=10, dim=True))
        self._tl_combo = QComboBox()
        self._tl_combo.addItems(["Hourly","Daily","Weekly"])
        self._tl_combo.setFixedWidth(100)
        self._tl_combo.currentIndexChanged.connect(lambda _: self._draw_timeline())
        row.addWidget(self._tl_combo)
        lo.addLayout(row)
        self._tl_inner = QWidget()
        tl = QVBoxLayout(self._tl_inner); tl.setContentsMargins(0,0,0,0)
        self._tl_ph = lbl("No timestamp data in this log.", dim=True, size=11)
        self._tl_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tl.addWidget(self._tl_ph)
        lo.addWidget(self._tl_inner, 1)

    # ── Tab: Users ───────────────────────────
    def _build_users(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20)
        lo.addWidget(lbl("Targeted Accounts", size=13, bold=True))
        lo.addWidget(lbl("Brute-force username frequency", dim=True, size=11))
        lo.addSpacing(10)
        self._usr_inner = QWidget()
        ul = QVBoxLayout(self._usr_inner); ul.setContentsMargins(0,0,0,0)
        self._usr_ph = lbl("No user data in this log.", dim=True, size=11)
        self._usr_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ul.addWidget(self._usr_ph)
        lo.addWidget(self._usr_inner, 1)

    # ── Tab: Patterns ────────────────────────
    def _build_patterns(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(14)
        lo.addWidget(lbl("Attack Patterns", size=13, bold=True))
        lo.addWidget(lbl("Subnet clustering and port analysis", dim=True, size=11))
        lo.addSpacing(4)

        # Subnets
        lo.addWidget(lbl("/24 Subnet Activity", size=11, bold=True))
        self._tree_sub = QTreeWidget()
        self._tree_sub.setColumnCount(3)
        self._tree_sub.setHeaderLabels(["Subnet /24", "Distinct IPs", "Total Events"])
        self._tree_sub.setRootIsDecorated(False); self._tree_sub.setAlternatingRowColors(True)
        hv = self._tree_sub.header()
        for i in range(3): hv.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        lo.addWidget(self._tree_sub, 1)

        lo.addWidget(sep())

        # Ports
        lo.addWidget(lbl("Target Port Distribution", size=11, bold=True))
        self._tree_ports = QTreeWidget()
        self._tree_ports.setColumnCount(2)
        self._tree_ports.setHeaderLabels(["Port", "Attempts"])
        self._tree_ports.setRootIsDecorated(False); self._tree_ports.setAlternatingRowColors(True)
        self._tree_ports.setMaximumHeight(150)
        hv2 = self._tree_ports.header()
        for i in range(2): hv2.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        lo.addWidget(self._tree_ports)

    # ── Tab: Intel Map ───────────────────────
    def _build_intel(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(0,0,0,0)
        lo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        center = QWidget(); center.setMaximumWidth(460)
        cl = QVBoxLayout(center); cl.setContentsMargins(40,60,40,60); cl.setSpacing(12)

        cl.addWidget(lbl("Threat Map", size=22, bold=True))
        cl.addWidget(lbl("Interactive choropleth and 3D globe.\nOpens securely in browser.",
                         dim=True, size=12))
        cl.addSpacing(20)

        self._btn_map_2d = QPushButton("Open 2D Choropleth Map")
        self._btn_map_2d.setObjectName("primary"); self._btn_map_2d.setFixedHeight(40)
        self._btn_map_2d.setEnabled(False)
        self._btn_map_2d.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_map_2d.clicked.connect(self._map_2d)
        cl.addWidget(self._btn_map_2d)

        self._btn_map_3d = QPushButton("Open 3D Globe")
        self._btn_map_3d.setFixedHeight(36)
        self._btn_map_3d.setEnabled(False)
        self._btn_map_3d.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_map_3d.clicked.connect(self._map_3d)
        cl.addWidget(self._btn_map_3d)

        lo.addStretch()
        lo.addWidget(center, 0, Qt.AlignmentFlag.AlignCenter)
        lo.addStretch()

    # ── Tab: AEGIS ───────────────────────────
    def _build_aegis(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(24,20,24,20); lo.setSpacing(14)

        lo.addWidget(lbl("AEGIS  —  Active Defense Engine", size=14, bold=True))
        warn = QLabel("⚠  This engine makes live changes to your Sophos Firewall configuration.")
        warn.setStyleSheet(f"color:{T("WARN")}; font-size:11px; background:transparent;")
        lo.addWidget(warn); lo.addWidget(sep())

        # Credentials
        cred = QGroupBox("SOPHOS API CREDENTIALS")
        gl = QHBoxLayout(cred); gl.setSpacing(20); gl.setContentsMargins(16,14,16,14)

        def field(ph, pw=False, w=140):
            e = QLineEdit(); e.setPlaceholderText(ph); e.setFixedWidth(w)
            if pw: e.setEchoMode(QLineEdit.EchoMode.Password)
            return e

        pairs_left  = [("Firewall IP", field("192.168.1.1")),
                       ("Username",    field("admin"))]
        pairs_right = [("Port",        field("4444", w=80)),
                       ("Password",    field("••••••", pw=True))]

        self.fw_ip,  self.fw_user = pairs_left[0][1],  pairs_left[1][1]
        self.fw_port,self.fw_pass = pairs_right[0][1], pairs_right[1][1]
        self.fw_port.setText("4444")

        for pairs in [pairs_left, pairs_right]:
            col = QWidget(); cl2 = QVBoxLayout(col); cl2.setSpacing(8); cl2.setContentsMargins(0,0,0,0)
            for label, widget in pairs:
                r = QHBoxLayout(); r.setSpacing(8)
                lb = lbl(label, size=10, dim=True); lb.setFixedWidth(80)
                r.addWidget(lb); r.addWidget(widget); cl2.addLayout(r)
            gl.addWidget(col)
        gl.addStretch()
        lo.addWidget(cred)

        # Action row
        ar = QHBoxLayout(); ar.setSpacing(12)
        ar.addWidget(lbl("Inject:", size=10, dim=True))
        self._combo_lim = QComboBox()
        self._combo_lim.addItems(["Top 10","Top 25","Top 50","Top 100","All IPs"])
        self._combo_lim.setFixedWidth(110)
        ar.addWidget(self._combo_lim)
        self._chk_dry = QCheckBox("Dry run (simulate only)")
        ar.addWidget(self._chk_dry); ar.addStretch()
        self._btn_aegis = QPushButton("Inject rules into firewall")
        self._btn_aegis.setObjectName("danger"); self._btn_aegis.setFixedHeight(36)
        self._btn_aegis.setEnabled(False)
        self._btn_aegis.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_aegis.clicked.connect(self._aegis_run)
        ar.addWidget(self._btn_aegis)
        lo.addLayout(ar)

        lo.addWidget(sep())
        lo.addWidget(lbl("Console", size=10, dim=True))
        self._console = QTextEdit(); self._console.setObjectName("console")
        self._console.setReadOnly(True)
        self._console.setText("AEGIS standby — awaiting analysis\n")
        lo.addWidget(self._console, 1)

    # ── Tab: History ─────────────────────────
    def _build_history(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(12)
        lo.addWidget(lbl("Analysis History", size=13, bold=True))

        self._hist_tbl = QTableWidget(0, 5)
        self._hist_tbl.setHorizontalHeaderLabels(["Date / Time","File","IPs","Events","Countries"])
        self._hist_tbl.setAlternatingRowColors(True)
        self._hist_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._hist_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        hv = self._hist_tbl.horizontalHeader()
        hv.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed); self._hist_tbl.setColumnWidth(0,160)
        hv.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in [2,3,4]:
            hv.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
            self._hist_tbl.setColumnWidth(i, 80)
        lo.addWidget(self._hist_tbl, 1)

        btn = QPushButton("Clear history"); btn.setFixedWidth(120)
        btn.clicked.connect(lambda: (self._hist.clear(), self._hist_tbl.setRowCount(0)))
        lo.addWidget(btn)

    # ─────────────────────────────────────────
    #  TEMA
    # ─────────────────────────────────────────
    def _toggle_theme(self):
        global _T, SEV_COLOR
        self._dark = not self._dark
        _T = THEMES["dark"] if self._dark else THEMES["light"]
        _update_sev_colors()

        self.setStyleSheet(_build_qss())

        icon = "●  Dark" if self._dark else "○  Light"
        self._btn_theme.setText(icon)

        # Redibujar gráficos si hay datos
        if self.df is not None:
            self._draw_dashboard(self.df)
            self._draw_geo(self.df)
            self._draw_users(self.df)
            self._draw_timeline()

    # ─────────────────────────────────────────
    #  LÓGICA
    # ─────────────────────────────────────────
    def _load(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Open Sophos Log", "",
            "CSV files (*.csv);;All files (*.*)")
        if f:
            self._file = f
            name = os.path.basename(f)
            disp = name if len(name) <= 28 else name[:25]+"..."
            self._file_lbl.setText(disp)
            self._file_lbl.setStyleSheet(f"color:{T("ACCENT")}; font-size:10px; background:transparent;")
            self._tb_file.setText(name)
            self._tb_file.setStyleSheet(f"color:{T("INK2")}; font-size:10px; background:transparent;")
            self.btn_run.setEnabled(True)

    def _run(self):
        if not hasattr(self,'_file'): return
        self.btn_run.setEnabled(False); self.btn_run.setText("Analyzing…")
        self._btn_map_2d.setEnabled(False); self._btn_map_3d.setEnabled(False)
        self._btn_aegis.setEnabled(False); self.btn_export.setEnabled(False)
        self._pbar.setVisible(True)
        self._console_write(f"Analysis started  {datetime.now().strftime('%H:%M:%S')}")

        self._aw = AnalysisWorker(self._file, list(self._wl))
        self._aw.progress_btn.connect(self.btn_run.setText)
        self._aw.log.connect(self._console_write)
        self._aw.finished.connect(self._on_done)
        self._aw.error.connect(self._on_err)
        self._aw.start()

    def _on_done(self, df, df_map, n_ips, n_events):
        self.df     = df
        self.df_map = df_map

        self._update_all(n_ips, n_events)

        self._btn_map_2d.setEnabled(True); self._btn_map_3d.setEnabled(True)
        self._btn_aegis.setEnabled(True);  self.btn_export.setEnabled(True)
        self.btn_run.setEnabled(True);     self.btn_run.setText("Run analysis")
        self._pbar.setVisible(False)

        self._add_history(n_ips, n_events)
        self._console_write(f"Done  ·  {n_ips} IPs  ·  {n_events} events")
        self._dash_status.setText(
            f"Analysis complete  ·  {n_ips} unique IPs  ·  "
            f"{n_events} events  ·  {df['Pais'].nunique()} countries")

        QMessageBox.information(self, "KATANA",
            f"Analysis complete.\n\n"
            f"  {n_ips} unique attacker IPs\n"
            f"  {n_events} total events\n"
            f"  {df['Pais'].nunique()} countries of origin")

    def _on_err(self, msg):
        self.btn_run.setEnabled(True); self.btn_run.setText("Run analysis")
        self._pbar.setVisible(False)
        QMessageBox.critical(self, "Analysis Error", msg)

    # ─── Update everything ────────────────────
    def _update_all(self, n_ips, n_events):
        df = self.df
        crit = df[df['Severidad']=='CRITICAL']['IP_Atacante'].nunique() \
               if 'Severidad' in df.columns else 0
        usr  = df[df['Usuario']!='—']['Usuario'].nunique() \
               if 'Usuario' in df.columns else 0

        # Sidebar metrics
        self.m_ips.set(n_ips); self.m_events.set(n_events)
        self.m_ctrs.set(df['Pais'].nunique()); self.m_crit.set(crit)

        # Dashboard KPIs
        for k,v in [("events",n_events),("ips",n_ips),("countries",df['Pais'].nunique()),
                    ("critical",crit),("users",usr)]:
            self._kpi[k].set(v)

        self._draw_table(df)
        self._draw_dashboard(df)
        self._draw_geo(df)
        self._draw_timeline()
        self._draw_users(df)
        self._draw_patterns(df)

    def _draw_table(self, df):
        self.tree.clear()
        cnt = df.groupby(['Pais','IP_Atacante']).size().reset_index(name='N')
        if 'Severidad' in df.columns:
            sm = df[['IP_Atacante','Severidad']].drop_duplicates().set_index('IP_Atacante')['Severidad']
            cnt['S'] = cnt['IP_Atacante'].map(sm).fillna('LOW')
        else: cnt['S'] = 'LOW'
        cnt = cnt.sort_values('N', ascending=False)

        for _, r in cnt.iterrows():
            c  = SEV_COLOR.get(r['S'], T("INK2"))
            it = QTreeWidgetItem([r['S'], str(r['Pais']),
                                  str(r['IP_Atacante']), str(r['N'])])
            it.setForeground(0, QBrush(QColor(c)))
            it.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
            it.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tree.addTopLevelItem(it)
        self._ip_count.setText(str(len(cnt)))

    def _draw_dashboard(self, df):
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FC

        plt.rcParams.update({'font.family': 'monospace'})
        surf = _T['SURFACE']; ink2 = _T['INK2']; acc = _T['ACCENT']
        brd  = _T['BORDER'];  brd2 = _T['BORDER2']; dim = _T['INK_DIM']

        def clear_panel(panel):
            inner = panel._inner
            while inner.layout().count():
                item = inner.layout().takeAt(0)
                if item.widget(): item.widget().deleteLater()

        # Left: countries bar
        clear_panel(self._dash_left)
        top_p = df['Pais'].value_counts().head(10)
        fig, ax = plt.subplots(figsize=(5, 3.4))
        fig.patch.set_facecolor(surf); ax.set_facecolor(surf)
        colors = [acc if i == 0 else brd2 for i in range(len(top_p))]
        ax.barh(range(len(top_p)), top_p.values, color=colors, height=0.6)
        ax.set_yticks(range(len(top_p)))
        ax.set_yticklabels([str(p)[:16] for p in top_p.index],
                           fontsize=8, color=ink2, fontfamily='monospace')
        ax.tick_params(axis='x', colors=dim, labelsize=8)
        ax.spines[['top','right','left']].set_visible(False)
        ax.spines['bottom'].set_color(brd)
        ax.set_facecolor(surf); fig.patch.set_facecolor(surf)
        fig.tight_layout(pad=0.8)
        self._dash_left._inner.layout().addWidget(FC(fig))
        self._dash_left._placeholder.setVisible(False)

        # Right: severity donut
        clear_panel(self._dash_right)
        if 'Severidad' in df.columns:
            sc = df.drop_duplicates('IP_Atacante')['Severidad'].value_counts()
        else:
            sc = {"LOW": df['IP_Atacante'].nunique()}
        labels = list(sc.index); vals = list(sc.values)
        clrs = [SEV_COLOR.get(l, dim) for l in labels]

        fig2, ax2 = plt.subplots(figsize=(5, 3.4))
        fig2.patch.set_facecolor(surf); ax2.set_facecolor(surf)
        wedges, texts, autos = ax2.pie(
            vals, labels=labels, colors=clrs, autopct='%1.0f%%',
            startangle=90, pctdistance=0.78,
            wedgeprops=dict(width=0.5, edgecolor=surf, linewidth=2))
        for t2 in texts:  t2.set_color(ink2); t2.set_fontsize(9)
        for a in autos:   a.set_color('white'); a.set_fontsize(8); a.set_fontweight('bold')
        ax2.set_facecolor(surf); fig2.patch.set_facecolor(surf)
        fig2.tight_layout(pad=0.4)
        self._dash_right._inner.layout().addWidget(FC(fig2))
        self._dash_right._placeholder.setVisible(False)

        plt.close('all')

    def _draw_geo(self, df):
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FC

        surf = _T['SURFACE']; ink2 = _T['INK2']; acc  = _T['ACCENT']
        brd  = _T['BORDER'];  dim  = _T['INK_DIM']

        inner_lo = self._geo_inner.layout()
        while inner_lo.count():
            it = inner_lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()

        top_p = df['Pais'].value_counts().head(15)
        fig, ax = plt.subplots(figsize=(9, 5))
        fig.patch.set_facecolor(surf); ax.set_facecolor(surf)

        idx = range(len(top_p))
        colors = [acc if i == 0 else (_T['BORDER2'] if i > 2 else ink2) for i in idx]
        ax.bar(idx, top_p.values, color=colors, width=0.6)
        ax.set_xticks(list(idx))
        ax.set_xticklabels([str(p)[:14] for p in top_p.index],
                           rotation=35, ha='right', fontsize=9,
                           color=ink2, fontfamily='monospace')
        ax.tick_params(axis='y', colors=dim, labelsize=9)
        ax.spines[['top','right']].set_visible(False)
        ax.spines['bottom'].set_color(brd); ax.spines['left'].set_color(brd)
        ax.set_facecolor(surf); fig.patch.set_facecolor(surf)
        ax.grid(axis='y', color=brd, linewidth=0.5)
        fig.tight_layout(pad=1.0)
        self._geo_inner.layout().addWidget(FC(fig))
        self._geo_ph.setVisible(False)
        plt.close('all')

    def _draw_timeline(self):
        if self.df is None: return
        df = self.df
        if 'Timestamp' not in df.columns or df['Timestamp'].isna().all():
            self._tl_ph.setVisible(True); return

        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FC

        inner_lo = self._tl_inner.layout()
        while inner_lo.count():
            it = inner_lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()

        gran = self._tl_combo.currentText()
        df_t = df.dropna(subset=['Timestamp']).copy()
        if gran == "Hourly":   df_t['B'] = df_t['Timestamp'].dt.floor('h')
        elif gran == "Daily":  df_t['B'] = df_t['Timestamp'].dt.date
        else:                  df_t['B'] = df_t['Timestamp'].dt.to_period('W').dt.start_time

        serie = df_t.groupby('B').size()
        if serie.empty: self._tl_ph.setVisible(True); return

        surf = _T['SURFACE']; ink2 = _T['INK2']; acc  = _T['ACCENT']
        brd  = _T['BORDER'];  dim  = _T['INK_DIM']; dng = _T['DANGER']

        self._tl_ph.setVisible(False)
        fig, ax = plt.subplots(figsize=(9, 4))
        fig.patch.set_facecolor(surf); ax.set_facecolor(surf)
        x = range(len(serie))
        ax.fill_between(x, serie.values, alpha=0.12, color=acc)
        ax.plot(x, serie.values, color=acc, linewidth=1.5,
                marker='o', markersize=3, markerfacecolor=dng, markeredgecolor=surf)
        n = max(1, len(serie)//10)
        ax.set_xticks(list(x)[::n])
        ax.set_xticklabels([str(k) for k in serie.index[::n]],
                           rotation=35, ha='right', fontsize=8, color=ink2, fontfamily='monospace')
        ax.tick_params(axis='y', colors=dim, labelsize=8)
        ax.spines[['top','right']].set_visible(False)
        ax.spines['bottom'].set_color(brd); ax.spines['left'].set_color(brd)
        ax.grid(axis='y', color=brd, linewidth=0.5)
        ax.set_facecolor(surf); fig.patch.set_facecolor(surf)
        fig.tight_layout(pad=1.0)
        self._tl_inner.layout().addWidget(FC(fig))
        plt.close('all')

    def _draw_users(self, df):
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FC

        inner_lo = self._usr_inner.layout()
        while inner_lo.count():
            it = inner_lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()

        if 'Usuario' not in df.columns:
            self._usr_ph.setVisible(True); return
        top_u = df[df['Usuario'] != '—']['Usuario'].value_counts().head(12)
        if top_u.empty: self._usr_ph.setVisible(True); return

        surf = _T['SURFACE']; ink2 = _T['INK2']; brd  = _T['BORDER']
        brd2 = _T['BORDER2']; dim  = _T['INK_DIM']; wrn = _T['WARN']

        self._usr_ph.setVisible(False)
        fig, ax = plt.subplots(figsize=(9, 5))
        fig.patch.set_facecolor(surf); ax.set_facecolor(surf)
        colors = [wrn if i == 0 else brd2 for i in range(len(top_u))]
        top_u.sort_values().plot(kind='barh', ax=ax, color=colors, width=0.6)
        ax.tick_params(axis='y', colors=ink2, labelsize=9, labelright=False)
        ax.tick_params(axis='x', colors=dim, labelsize=9)
        ax.spines[['top','right']].set_visible(False)
        ax.spines['bottom'].set_color(brd); ax.spines['left'].set_color(brd)
        ax.grid(axis='x', color=brd, linewidth=0.5)
        ax.set_facecolor(surf); fig.patch.set_facecolor(surf)
        fig.tight_layout(pad=1.0)
        self._usr_inner.layout().addWidget(FC(fig))
        plt.close('all')

    def _draw_patterns(self, df):
        self._tree_sub.clear()
        df2 = df.copy()
        df2['Sub'] = df2['IP_Atacante'].str.extract(r'^(\d+\.\d+\.\d+)\.')
        sr = df2.groupby('Sub').agg(
            IPs=('IP_Atacante','nunique'), Total=('IP_Atacante','count')
        ).reset_index().sort_values('Total', ascending=False).head(20)
        for _, r in sr.iterrows():
            it = QTreeWidgetItem([f"{r['Sub']}.0/24", str(r['IPs']), str(r['Total'])])
            it.setForeground(0, QBrush(QColor(ACCENT)))
            it.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
            it.setTextAlignment(2, Qt.AlignmentFlag.AlignCenter)
            self._tree_sub.addTopLevelItem(it)

        self._tree_ports.clear()
        if 'Puerto' in df.columns:
            for p, n in df[df['Puerto'] != '—']['Puerto'].value_counts().head(15).items():
                it = QTreeWidgetItem([str(p), str(n)])
                it.setForeground(0, QBrush(QColor(WARN)))
                it.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
                self._tree_ports.addTopLevelItem(it)

    # ─── Filter table ────────────────────────
    def _filter_table(self, ip_f, country_f, sev_f):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            it = root.child(i)
            show = True
            if ip_f and ip_f.lower() not in it.text(2).lower(): show = False
            if country_f and country_f.lower() not in it.text(1).lower(): show = False
            if sev_f != "All" and it.text(0) != sev_f: show = False
            it.setHidden(not show)

    # ─── Maps ────────────────────────────────
    def _map_2d(self):
        if not self.df_map: return
        import plotly.express as px
        fig = px.choropleth(self.df_map, locations="Pais", locationmode="country names",
                            color="Total_Ataques", hover_name="Pais",
                            color_continuous_scale="Blues",
                            title="KATANA v7.0  ·  Global Attack Distribution")
        fig.update_layout(
            paper_bgcolor=T("SURFACE"), plot_bgcolor=T("SURFACE"),
            font=dict(family="IBM Plex Sans, sans-serif", color=T("INK")),
            geo=dict(showframe=False, showcoastlines=True,
                     coastlinecolor=T("BORDER2"), bgcolor=T("BG"),
                     projection_type='equirectangular'))
        p = os.path.abspath("katana_map.html"); fig.write_html(p); webbrowser.open(f"file://{p}")

    def _map_3d(self):
        if self.df is None: return
        try:
            import plotly.express as px
            df = self.df.dropna(subset=['Lat','Lon'])
            df = df[df['Lat'] != 0.0]
            cnt = df.groupby(['IP_Atacante','Pais','Lat','Lon']).size().reset_index(name='Events')
            fig = px.scatter_geo(
                cnt, lat='Lat', lon='Lon', color='Events',
                hover_name='IP_Atacante', size='Events', size_max=28,
                color_continuous_scale="Blues",
                projection='orthographic',
                title="KATANA v7.0  ·  3D Attack Globe")
            fig.update_layout(
                paper_bgcolor=T("SURFACE"),
                font=dict(family="IBM Plex Sans, sans-serif", color=T("INK")),
                geo=dict(bgcolor="#F0F0EE", showland=True, landcolor="#E8E8E4",
                         showocean=True, oceancolor="#D8E8F4",
                         showcoastlines=True, coastlinecolor=T("BORDER2")))
            p = os.path.abspath("katana_globe.html"); fig.write_html(p); webbrowser.open(f"file://{p}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ─── AEGIS ───────────────────────────────
    def _aegis_run(self):
        if self.df is None: return
        fw_ip  = self.fw_ip.text().strip()
        fw_prt = self.fw_port.text().strip()
        fw_usr = self.fw_user.text().strip()
        fw_pw  = self.fw_pass.text().strip()
        dry    = self._chk_dry.isChecked()

        if not dry and not all([fw_ip, fw_prt, fw_usr, fw_pw]):
            QMessageBox.warning(self, "AEGIS", "Fill in all firewall credentials."); return

        sel = self._combo_lim.currentText()
        ips = (self.df['IP_Atacante'].value_counts().index.tolist() if sel == "All IPs"
               else self.df['IP_Atacante'].value_counts().head(int(sel.split()[1])).index.tolist())

        mode = "DRY RUN" if dry else f"LIVE  [{fw_ip}]"
        if not dry:
            r = QMessageBox.question(
                self, "Confirm AEGIS",
                f"Mode: {mode}\nIPs to inject: {len(ips)}\n\nProceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes: return

        self._btn_aegis.setEnabled(False); self._btn_aegis.setText("Running…")
        self._console_write(f"\nAEGIS  →  {mode}  ·  {len(ips)} targets")

        self._egw = AegisWorker(fw_ip, fw_prt, fw_usr, fw_pw, ips, dry=dry)
        self._egw.log.connect(self._console_write)
        self._egw.finished.connect(self._aegis_done)
        self._egw.start()

    def _aegis_done(self, ok, total):
        self._console_write(f"\nAEGIS complete  ·  {ok}/{total} IPs processed")
        self._btn_aegis.setEnabled(True); self._btn_aegis.setText("Inject rules into firewall")

    # ─── History ─────────────────────────────
    def _add_history(self, n_ips, n_events):
        entry = {"ts": datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
                 "file": os.path.basename(getattr(self,'_file','—')),
                 "ips": n_ips, "events": n_events,
                 "countries": self.df['Pais'].nunique()}
        self._hist.append(entry)
        r = self._hist_tbl.rowCount(); self._hist_tbl.insertRow(r)
        for c, k in enumerate(["ts","file","ips","events","countries"]):
            it = QTableWidgetItem(str(entry[k]))
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._hist_tbl.setItem(r, c, it)

    # ─── Context menus ───────────────────────
    def _ip_menu(self):
        m = QMenu(self)
        m.addAction("Copy all IPs to clipboard", self._copy_all_ips)
        m.addAction("Export visible IPs as IOC",  self._export_visible_ioc)
        m.addSeparator()
        m.addAction("Sort by attempts ↓",
                    lambda: self.tree.sortByColumn(3, Qt.SortOrder.DescendingOrder))
        m.exec(QCursor.pos())

    def _row_menu(self, pos):
        it = self.tree.itemAt(pos)
        if not it: return
        ip = it.text(2); m = QMenu(self)
        m.addAction(f"Copy  {ip}", lambda: QApplication.clipboard().setText(ip))
        m.addAction(f"Add to whitelist",
                    lambda: (self._wl.add(ip),
                             QMessageBox.information(self,"Whitelist",f"{ip} added.")))
        m.addSeparator()
        m.addAction("VirusTotal  ↗",
                    lambda: webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}"))
        m.addAction("AbuseIPDB  ↗",
                    lambda: webbrowser.open(f"https://www.abuseipdb.com/check/{ip}"))
        m.addAction("Shodan  ↗",
                    lambda: webbrowser.open(f"https://www.shodan.io/host/{ip}"))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _copy_all_ips(self):
        if self.df is None: return
        QApplication.clipboard().setText("\n".join(self.df['IP_Atacante'].unique()))

    def _export_visible_ioc(self):
        root = self.tree.invisibleRootItem()
        ips  = [root.child(i).text(2) for i in range(root.childCount())
                if not root.child(i).isHidden()]
        p = f"IOC_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(p,'w') as f:
            f.write(f"# KATANA IOC  {datetime.now()}\n"); f.write("\n".join(ips))
        QMessageBox.information(self, "Exported", f"{len(ips)} IPs → {p}")

    # ─── Whitelist ───────────────────────────
    def _whitelist_dlg(self):
        d = WhitelistDialog(self._wl, self); d.exec()

    # ─── Export ──────────────────────────────
    def _export(self):
        if self.df is None: return
        ExportDialog(self.df, self.df_map, self).exec()

    # ─── Console ─────────────────────────────
    def _console_write(self, text):
        self._console.append(text)
        sb = self._console.verticalScrollBar(); sb.setValue(sb.maximum())


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = KatanaApp(); w.show()
    sys.exit(app.exec())