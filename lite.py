"""
KATANA Lite  ·  Threat Intelligence Platform
Sophos Firewall Log Analyzer
─────────────────────────────────────────────
Stack:
  UI       → PyQt6
  Gráficos → pyqtgraph
  PDF      → reportlab
  Datos    → pandas
  Mapas    → plotly (browser, solo 2D)
  DB       → sqlite3 (historial persistente)

Versión Lite — incluye:
  · Cargar CSV log
  · Lanzamiento de analíticas
  · Exportar datos (solo PDF)
  · Bloque izquierdo (Métricas / Lista IP / Filtros)
  · Dashboard · Geography · Timeline · Users
  · Intel Map 2D · History
  · Modo Light / Dark
"""

import sys, os, re, time, traceback, webbrowser, warnings, sqlite3
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import numpy as np
import requests
import pandas as pd

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFileDialog, QMessageBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit, QComboBox,
    QFrame, QHeaderView, QProgressBar, QSplitter, QCheckBox,
    QAbstractItemView, QDialog, QDialogButtonBox, QTableWidget,
    QTableWidgetItem, QSizePolicy, QMenu,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QCursor, QBrush, QPainter, QFont

import pyqtgraph as pg

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─────────────────────────────────────────────────────────────────────────────
#  BASE DE DATOS  (historial persistente — sin whitelist en Lite)
# ─────────────────────────────────────────────────────────────────────────────
DB_PATH = Path.home() / ".katana_lite.db"

def _init_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT,
            filename TEXT,
            n_ips    INTEGER,
            n_events INTEGER,
            n_ctrs   INTEGER
        )""")
    con.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip      TEXT PRIMARY KEY,
            country TEXT,
            lat     REAL,
            lon     REAL,
            ts      INTEGER DEFAULT (strftime('%s','now'))
        )""")
    con.commit()
    return con

_DB = _init_db()

def db_history_add(ts, filename, n_ips, n_events, n_ctrs):
    _DB.execute(
        "INSERT INTO history (ts,filename,n_ips,n_events,n_ctrs) VALUES (?,?,?,?,?)",
        (ts, filename, n_ips, n_events, n_ctrs))
    _DB.commit()

def db_history_load():
    return _DB.execute(
        "SELECT ts,filename,n_ips,n_events,n_ctrs FROM history ORDER BY id DESC LIMIT 200"
    ).fetchall()

def db_history_clear():
    _DB.execute("DELETE FROM history"); _DB.commit()

_GEO_TTL = 30 * 86400

def db_geo_load(ips: list) -> dict:
    if not ips:
        return {}
    now = int(time.time())
    placeholders = ",".join("?" * len(ips))
    rows = _DB.execute(
        f"SELECT ip,country,lat,lon,ts FROM geo_cache WHERE ip IN ({placeholders})", ips
    ).fetchall()
    return {r[0]: (r[1], r[2], r[3]) for r in rows if (now - r[4]) < _GEO_TTL}

def db_geo_save(results: dict):
    now = int(time.time())
    con = sqlite3.connect(DB_PATH)
    con.executemany(
        "INSERT OR REPLACE INTO geo_cache (ip,country,lat,lon,ts) VALUES (?,?,?,?,?)",
        [(ip, v[0], v[1], v[2], now) for ip, v in results.items()]
    )
    con.commit(); con.close()

# ─────────────────────────────────────────────────────────────────────────────
#  TEMA  (Light / Dark)
# ─────────────────────────────────────────────────────────────────────────────
MONO = "'JetBrains Mono','IBM Plex Mono','Consolas','Courier New',monospace"
SANS = "'Poppins','Segoe UI','Helvetica Neue',sans-serif"

THEMES = {
    "dark": {
        "BG":       "#1C1C1E", "SURFACE":  "#2C2C2E", "SURFACE2": "#3A3A3C",
        "BORDER":   "#3A3A3C", "BORDER2":  "#48484A",
        "INK":      "#F2F2F7", "INK2":     "#AEAEB2", "INK_DIM":  "#636366",
        "ACCENT":   "#0A84FF", "ACCENT_D": "#0060CC",
        "DANGER":   "#FF453A", "SUCCESS":  "#30D158", "WARN":     "#FF9F0A",
        "S_CRIT":   "#FF453A", "S_HIGH":   "#FF9F0A",
        "S_MED":    "#0A84FF", "S_LOW":    "#30D158",
        "CON_BG":   "#161618", "CON_FG":   "#7AE47A",
    },
    "light": {
        "BG":       "#F0EFEB", "SURFACE":  "#FAFAF8", "SURFACE2": "#EEECEA",
        "BORDER":   "#D8D6D0", "BORDER2":  "#C2C0BA",
        "INK":      "#1C1C1E", "INK2":     "#4A4A50", "INK_DIM":  "#8E8E93",
        "ACCENT":   "#007AFF", "ACCENT_D": "#005EC4",
        "DANGER":   "#C0392B", "SUCCESS":  "#1A7A42", "WARN":     "#C06010",
        "S_CRIT":   "#C0392B", "S_HIGH":   "#C06010",
        "S_MED":    "#007AFF", "S_LOW":    "#1A7A42",
        "CON_BG":   "#1C1C1E", "CON_FG":   "#5EDB5E",
    },
}

_T      = THEMES["dark"]
ACCENT  = _T["ACCENT"]
WARN    = _T["WARN"]
SEV_COLOR = {}

def T(k): return _T[k]

def _update_globals():
    global _T, ACCENT, WARN, SEV_COLOR
    ACCENT = _T["ACCENT"]; WARN = _T["WARN"]
    SEV_COLOR = {
        "CRITICAL": _T["S_CRIT"], "HIGH": _T["S_HIGH"],
        "MEDIUM":   _T["S_MED"],  "LOW":  _T["S_LOW"],
    }

_update_globals()


def _build_qss() -> str:
    t = _T
    return f"""
/* ── Base ── */
* {{ font-family:{SANS}; font-size:12px; color:{t['INK']}; outline:none; }}
QMainWindow,QDialog {{ background:{t['BG']}; }}
QWidget {{ background:transparent; color:{t['INK']}; }}

/* ── Estructuras ── */
#sidebar  {{ background:{t['SURFACE']}; border-right:1px solid {t['BORDER']}; }}
#topbar   {{ background:{t['SURFACE']}; border-bottom:1px solid {t['BORDER']}; }}
#card     {{ background:{t['SURFACE']}; border:1px solid {t['BORDER']}; border-radius:6px; }}

/* ── Botones — jerarquía visual clara ── */
QPushButton {{
    background:{t['SURFACE2']}; color:{t['INK2']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:6px 14px; font-size:11px; font-weight:500;
}}
QPushButton:hover   {{ background:{t['BORDER2']}; color:{t['INK']}; }}
QPushButton:pressed {{ background:{t['BORDER']}; }}
QPushButton:disabled {{ color:{t['INK_DIM']}; border-color:{t['BORDER']}; background:{t['SURFACE']}; }}

/* Primary — máximo énfasis */
QPushButton#primary {{
    background:{t['ACCENT']}; color:white; border:none;
    font-weight:700; font-size:12px; letter-spacing:0.3px;
}}
QPushButton#primary:hover    {{ background:{t['ACCENT_D']}; }}
QPushButton#primary:disabled {{ background:{t['BORDER2']}; color:{t['INK_DIM']}; }}

/* Ghost — mínimo */
QPushButton#ghost {{
    background:transparent; border:none;
    color:{t['INK_DIM']}; padding:4px 8px; font-size:11px; font-weight:400;
}}
QPushButton#ghost:hover {{ color:{t['ACCENT']}; background:{t['ACCENT']}18; }}

/* Success */
QPushButton#success {{
    background:{t['SUCCESS']}12; color:{t['SUCCESS']};
    border:1px solid {t['SUCCESS']}44; border-radius:5px;
    font-weight:600; font-size:11px;
}}
QPushButton#success:hover    {{ background:{t['SUCCESS']}22; border-color:{t['SUCCESS']}; }}
QPushButton#success:disabled {{ color:{t['INK_DIM']}; border-color:{t['BORDER']}; background:transparent; }}

/* Theme toggle */
QPushButton#theme_btn {{
    background:{t['SURFACE2']}; border:1px solid {t['BORDER2']};
    color:{t['INK2']}; padding:3px 10px; border-radius:10px;
    font-size:10px; font-weight:500;
}}
QPushButton#theme_btn:hover {{ color:{t['INK']}; background:{t['BORDER2']}; }}

/* ── Tabs — bold cuando activo ── */
QTabWidget::pane {{
    background:{t['SURFACE']}; border:1px solid {t['BORDER']};
    border-top:none; border-radius:0 0 6px 6px;
}}
QTabBar {{ background:{t['BG']}; }}
QTabBar::tab {{
    background:transparent; color:{t['INK_DIM']};
    padding:8px 20px; border:none;
    border-bottom:2px solid transparent;
    font-size:11px; font-weight:500;
}}
QTabBar::tab:selected {{
    color:{t['INK']}; border-bottom:2px solid {t['ACCENT']};
    font-weight:700;
}}
QTabBar::tab:hover:!selected {{
    color:{t['INK2']}; border-bottom:2px solid {t['BORDER2']};
}}

/* ── Árbol de IPs — datos, fuente mono, weight normal (no compite con menús) ── */
QTreeWidget,QTableWidget {{
    background:{t['SURFACE']}; color:{t['INK2']};
    border:none; alternate-background-color:{t['BG']};
    gridline-color:{t['BORDER']};
    font-family:{MONO}; font-size:11px; font-weight:400;
    selection-background-color:{t['ACCENT']}28; selection-color:{t['INK']};
}}
QTreeWidget::item,QTableWidget::item {{
    padding:5px 10px; border-bottom:1px solid {t['BORDER']};
    color:{t['INK2']};
}}
QTreeWidget::item:selected,QTableWidget::item:selected {{
    background:{t['ACCENT']}28; color:{t['INK']};
    border-left:2px solid {t['ACCENT']}; font-weight:500;
}}
QTreeWidget::item:hover:!selected,QTableWidget::item:hover:!selected {{
    background:{t['SURFACE2']};
}}
/* Cabeceras — caps pequeñas, medium weight */
QHeaderView {{ background:{t['BG']}; }}
QHeaderView::section {{
    background:{t['BG']}; color:{t['INK_DIM']};
    border:none; border-bottom:1px solid {t['BORDER2']};
    border-right:1px solid {t['BORDER']};
    padding:6px 10px; font-size:9px; font-weight:700;
    letter-spacing:1px;
}}

/* ── Inputs ── */
QLineEdit {{
    background:{t['BG']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:6px 10px; font-weight:400;
    selection-background-color:{t['ACCENT']}44;
}}
QLineEdit:focus {{ border-color:{t['ACCENT']}; background:{t['SURFACE']}; }}

QComboBox {{
    background:{t['BG']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:5px 10px; min-width:100px; font-weight:400;
}}
QComboBox:focus {{ border-color:{t['ACCENT']}; }}
QComboBox::drop-down {{ border:none; width:18px; }}
QComboBox QAbstractItemView {{
    background:{t['SURFACE']}; color:{t['INK']};
    border:1px solid {t['BORDER2']};
    selection-background-color:{t['ACCENT']}28; selection-color:{t['INK']};
    font-weight:400;
}}

QTextEdit {{
    background:{t['SURFACE']}; color:{t['INK']};
    border:1px solid {t['BORDER']}; border-radius:5px;
    padding:6px; font-weight:400;
}}
QTextEdit#console {{
    background:{t['CON_BG']}; color:{t['CON_FG']};
    border:none; border-radius:5px;
    font-family:{MONO}; font-size:11px; padding:10px;
}}

/* ── Progreso ── */
QProgressBar {{
    background:{t['BORDER']}; border:none; border-radius:1px;
    height:2px; color:transparent;
}}
QProgressBar::chunk {{ background:{t['ACCENT']}; border-radius:1px; }}

/* ── Scrollbars ── */
QScrollBar:vertical {{ background:transparent; width:6px; border:none; }}
QScrollBar::handle:vertical {{ background:{t['BORDER2']}; border-radius:3px; min-height:24px; }}
QScrollBar::handle:vertical:hover {{ background:{t['INK_DIM']}; }}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ background:transparent; height:6px; border:none; }}
QScrollBar::handle:horizontal {{ background:{t['BORDER2']}; border-radius:3px; }}
QScrollBar::handle:horizontal:hover {{ background:{t['INK_DIM']}; }}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{ width:0; }}

QFrame[frameShape="4"],QFrame[frameShape="5"] {{
    color:{t['BORDER']}; background:{t['BORDER']}; max-height:1px; border:none;
}}

/* ── Menús — máximo peso, bien diferenciados ── */
QMenu {{
    background:{t['SURFACE']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; padding:4px; border-radius:8px;
}}
QMenu::item {{
    padding:7px 20px; font-size:12px; font-weight:600;
    border-radius:4px; color:{t['INK']};
}}
QMenu::item:selected {{
    background:{t['ACCENT']}28; color:{t['INK']};
    font-weight:700;
}}
QMenu::separator {{ height:1px; background:{t['BORDER']}; margin:4px 8px; }}

/* ── Mensajes y tooltips ── */
QMessageBox {{ background:{t['SURFACE']}; }}
QMessageBox QLabel {{ color:{t['INK']}; font-size:12px; font-weight:500; background:transparent; }}
QMessageBox QPushButton {{ min-width:80px; font-weight:600; }}

QLabel#lbl_dim {{ color:{t['INK_DIM']}; font-weight:400; }}
QLabel#section_title {{ color:{t['INK']}; font-weight:700; font-size:10px; letter-spacing:0.8px; }}
QCheckBox {{ color:{t['INK2']}; spacing:6px; font-size:11px; font-weight:400; }}
QCheckBox::indicator {{
    width:14px; height:14px; background:{t['BG']};
    border:1.5px solid {t['BORDER2']}; border-radius:3px;
}}
QCheckBox::indicator:checked {{ background:{t['ACCENT']}; border-color:{t['ACCENT']}; }}

QToolTip {{
    background:{t['SURFACE2']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; padding:4px 8px;
    border-radius:4px; font-size:11px; font-weight:500;
}}
"""

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS UI
# ─────────────────────────────────────────────────────────────────────────────
def sep(vertical=False):
    f = QFrame()
    f.setFrameShape(QFrame.Shape.VLine if vertical else QFrame.Shape.HLine)
    f.setFixedWidth(1) if vertical else f.setFixedHeight(1)
    return f

def lbl(text, size=12, color=None, bold=False, mono=False, dim=False):
    l = QLabel(text)
    family = MONO if mono else SANS
    weight = "600" if bold else "400"
    style  = f"font-family:{family};font-size:{size}px;font-weight:{weight};background:transparent;"
    if color:
        style += f"color:{color};"
    elif dim:
        l.setObjectName("lbl_dim")
    l.setStyleSheet(style)
    return l

def spacer(h=None, v=None):
    w = QWidget()
    if h: w.setFixedWidth(h)
    if v: w.setFixedHeight(v)
    w.setSizePolicy(
        QSizePolicy.Policy.Expanding if not h else QSizePolicy.Policy.Fixed,
        QSizePolicy.Policy.Expanding if not v else QSizePolicy.Policy.Fixed,
    )
    return w

# ─────────────────────────────────────────────────────────────────────────────
#  PYQTGRAPH HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _pg_bar(x_labels, values, color_first=None, title="") -> pg.PlotWidget:
    surf = _T["SURFACE"]; ink2 = _T["INK2"]; brd = _T["BORDER"]
    acc  = color_first or _T["ACCENT"]; brd2 = _T["BORDER2"]
    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.showGrid(x=True, y=False, alpha=0.15)
    pw.getAxis("bottom").setPen(pg.mkPen(brd))
    pw.getAxis("left").setPen(pg.mkPen(brd))
    pw.getAxis("left").setTextPen(pg.mkPen(ink2))
    pw.getAxis("bottom").setTextPen(pg.mkPen(ink2))
    if title:
        pw.setTitle(title, color=ink2, size="10pt")
    n = len(values)
    colors = [acc] + [brd2] * (n - 1)
    for i, (v, c) in enumerate(zip(values, colors)):
        bar = pg.BarGraphItem(x=[i], height=[v], width=0.6,
                              brush=pg.mkBrush(c), pen=pg.mkPen(None))
        pw.addItem(bar)
    ticks = [(i, str(x_labels[i])[:16]) for i in range(n)]
    pw.getAxis("bottom").setTicks([ticks])
    pw.getAxis("bottom").setStyle(tickTextOffset=4)
    pw.setMouseEnabled(x=False, y=False)
    pw.getViewBox().setDefaultPadding(0.05)
    return pw

def _pg_hbar(labels, values, color_first=None) -> pg.PlotWidget:
    surf = _T["SURFACE"]; ink2 = _T["INK2"]; brd = _T["BORDER"]
    wrn  = color_first or _T["WARN"]; brd2 = _T["BORDER2"]
    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.showGrid(x=True, y=False, alpha=0.15)
    pw.getAxis("bottom").setPen(pg.mkPen(brd))
    pw.getAxis("left").setPen(pg.mkPen(brd))
    pw.getAxis("left").setTextPen(pg.mkPen(ink2))
    pw.getAxis("bottom").setTextPen(pg.mkPen(ink2))
    n = len(values)
    colors = [wrn] + [brd2] * (n - 1)
    for i, (v, c) in enumerate(zip(values, colors)):
        bar = pg.BarGraphItem(x=[i], height=[v], width=0.6,
                              brush=pg.mkBrush(c), pen=pg.mkPen(None))
        pw.addItem(bar)
    ticks = [(i, str(labels[i])[:18]) for i in range(n)]
    pw.getAxis("bottom").setTicks([ticks])
    pw.setMouseEnabled(x=False, y=False)
    return pw

def _pg_line(x_vals, y_vals) -> pg.PlotWidget:
    surf = _T["SURFACE"]; ink2 = _T["INK2"]; brd = _T["BORDER"]
    acc  = _T["ACCENT"]; dng  = _T["DANGER"]
    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.showGrid(x=False, y=True, alpha=0.15)
    pw.getAxis("bottom").setPen(pg.mkPen(brd))
    pw.getAxis("left").setPen(pg.mkPen(brd))
    pw.getAxis("left").setTextPen(pg.mkPen(ink2))
    pw.getAxis("bottom").setTextPen(pg.mkPen(ink2))
    xs = list(range(len(y_vals)))
    fill = pg.FillBetweenItem(
        pg.PlotDataItem(xs, y_vals, pen=pg.mkPen(acc, width=1.5)),
        pg.PlotDataItem(xs, [0] * len(xs), pen=pg.mkPen(None)),
        brush=pg.mkBrush(acc + "22")
    )
    pw.addItem(fill)
    pw.plot(xs, y_vals, pen=pg.mkPen(acc, width=1.5),
            symbol="o", symbolSize=5,
            symbolBrush=pg.mkBrush(dng), symbolPen=pg.mkPen(None))
    n = max(1, len(xs) // 10)
    ticks = [(xs[i], str(x_vals[i])[:12]) for i in range(0, len(xs), n)]
    pw.getAxis("bottom").setTicks([ticks])
    pw.setMouseEnabled(x=False, y=False)
    return pw

def _pg_donut(labels, values) -> pg.PlotWidget:
    import math
    surf = _T["SURFACE"]
    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.hideAxis("bottom"); pw.hideAxis("left")
    pw.setAspectLocked(True)
    pw.setMouseEnabled(x=False, y=False)
    total = sum(values) or 1
    angle = 90.0
    for lab, val in zip(labels, values):
        span  = val / total * 360
        color = SEV_COLOR.get(lab, _T["INK_DIM"])
        pts_x, pts_y = [], []
        steps = max(4, int(span / 2))
        for s in range(steps + 1):
            a = math.radians(angle + s * span / steps)
            pts_x.append(math.cos(a) * 0.9)
            pts_y.append(math.sin(a) * 0.9)
        for s in range(steps, -1, -1):
            a = math.radians(angle + s * span / steps)
            pts_x.append(math.cos(a) * 0.5)
            pts_y.append(math.sin(a) * 0.5)
        curve = pg.PlotDataItem(
            pts_x + [pts_x[0]], pts_y + [pts_y[0]],
            fillLevel=0.0, brush=pg.mkBrush(color), pen=pg.mkPen(surf, width=2))
        pw.addItem(curve)
        mid_a = math.radians(angle + span / 2)
        txt = pg.TextItem(
            f"{lab}\n{val/total*100:.0f}%", anchor=(0.5, 0.5), color=_T["INK2"])
        txt.setFont(QFont("Consolas", 7))
        txt.setPos(math.cos(mid_a) * 1.15, math.sin(mid_a) * 1.15)
        pw.addItem(txt)
        angle += span
    return pw

# ─────────────────────────────────────────────────────────────────────────────
#  PDF  (reportlab — solo export disponible en Lite)
# ─────────────────────────────────────────────────────────────────────────────
def _build_pdf(df: pd.DataFrame, df_mapa, path: str):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        raise RuntimeError("reportlab no instalado.\nEjecuta:  pip install reportlab")

    BLUE   = rl_colors.HexColor("#0A84FF")
    GRAY   = rl_colors.HexColor("#8E8E93")
    DARK   = rl_colors.HexColor("#1C1C1E")
    RED    = rl_colors.HexColor("#FF453A")
    ORANGE = rl_colors.HexColor("#FF9F0A")
    GREEN  = rl_colors.HexColor("#30D158")
    WHITE  = rl_colors.white
    LTGRAY = rl_colors.HexColor("#F0EFEB")
    sev_color = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": BLUE, "LOW": GREEN}

    doc  = SimpleDocTemplate(path, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    ss   = getSampleStyleSheet()
    body = []

    h1  = ParagraphStyle("h1",  parent=ss["Normal"], fontSize=22, textColor=BLUE,
                          alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=4)
    sub = ParagraphStyle("sub", parent=ss["Normal"], fontSize=9, textColor=GRAY,
                          alignment=TA_CENTER, spaceAfter=12)
    sec = ParagraphStyle("sec", parent=ss["Normal"], fontSize=12, textColor=DARK,
                          fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4)
    kv  = ParagraphStyle("kv",  parent=ss["Normal"], fontSize=11,
                          textColor=DARK, spaceAfter=3)

    body.append(Paragraph("KATANA Lite — Executive Forensic Report", h1))
    body.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}"
        f"  |  {len(df):,} events analyzed", sub))
    body.append(HRFlowable(width="100%", color=GRAY, thickness=0.5, spaceAfter=10))

    # 1. Summary
    body.append(Paragraph("1.  INCIDENT SUMMARY", sec))
    crit = (df[df["Severidad"] == "CRITICAL"]["IP_Atacante"].nunique()
            if "Severidad" in df.columns else "N/A")
    for k, v in [("Total events",         f"{len(df):,}"),
                 ("Unique attacker IPs",   f"{df['IP_Atacante'].nunique():,}"),
                 ("Countries of origin",   f"{df['Pais'].nunique():,}"),
                 ("CRITICAL severity IPs", str(crit))]:
        body.append(Paragraph(f"<b>{k}:</b>  {v}", kv))
    body.append(Spacer(1, 10))

    # 2. Top countries
    body.append(Paragraph("2.  TOP 10 ATTACK ORIGINS", sec))
    total_ev = len(df)
    tdata = [["COUNTRY", "EVENTS", "% TOTAL"]]
    for c, n in df["Pais"].value_counts().head(10).items():
        tdata.append([str(c), f"{n:,}", f"{n/total_ev*100:.1f}%"])
    tbl = Table(tdata, colWidths=[9*cm, 4*cm, 4*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",    (0,0), (-1,0), WHITE),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [LTGRAY, WHITE]),
        ("GRID",         (0,0), (-1,-1), 0.25, GRAY),
        ("ALIGN",        (1,0), (-1,-1), "CENTER"),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]))
    body.append(tbl); body.append(Spacer(1, 10))

    # 3. Top IPs
    body.append(Paragraph("3.  TOP 15 IPs FOR BLACKLISTING", sec))
    top = df.groupby(["IP_Atacante", "Pais"]).size().reset_index(name="N")
    if "Severidad" in df.columns:
        sm = (df[["IP_Atacante","Severidad"]].drop_duplicates()
              .set_index("IP_Atacante")["Severidad"])
        top["S"] = top["IP_Atacante"].map(sm).fillna("LOW")
    else:
        top["S"] = "LOW"
    top = top.sort_values("N", ascending=False).head(15)
    tdata2 = [["IP ADDRESS", "COUNTRY", "EVENTS", "SEVERITY"]]
    for _, r in top.iterrows():
        tdata2.append([str(r["IP_Atacante"]), str(r["Pais"])[:22],
                       str(r["N"]), str(r["S"])])
    tbl2 = Table(tdata2, colWidths=[5*cm, 6*cm, 3*cm, 3*cm])
    row_styles = [
        ("BACKGROUND",   (0,0), (-1,0), DARK),
        ("TEXTCOLOR",    (0,0), (-1,0), WHITE),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("GRID",         (0,0), (-1,-1), 0.25, GRAY),
        ("ALIGN",        (2,0), (-1,-1), "CENTER"),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]
    for i, (_, r) in enumerate(top.iterrows(), 1):
        c = sev_color.get(str(r["S"]), GRAY)
        row_styles.append(("TEXTCOLOR", (3,i), (3,i), c))
        row_styles.append(("FONTNAME",  (3,i), (3,i), "Helvetica-Bold"))
    tbl2.setStyle(TableStyle(row_styles))
    body.append(tbl2); body.append(Spacer(1, 10))

    # 4. Users
    if "Usuario" in df.columns:
        uu = (df[~df["Usuario"].isin(["—","-","","nan"])]
              ["Usuario"].value_counts().head(10))
        if not uu.empty:
            body.append(Paragraph("4.  TARGETED ACCOUNTS (BRUTE FORCE)", sec))
            tdata3 = [["USERNAME", "ATTEMPTS"]]
            for u, n in uu.items():
                tdata3.append([str(u), str(n)])
            tbl3 = Table(tdata3, colWidths=[12*cm, 5*cm])
            tbl3.setStyle(TableStyle([
                ("BACKGROUND",   (0,0), (-1,0), ORANGE),
                ("TEXTCOLOR",    (0,0), (-1,0), WHITE),
                ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [LTGRAY, WHITE]),
                ("GRID",         (0,0), (-1,-1), 0.25, GRAY),
                ("ALIGN",        (1,0), (-1,-1), "CENTER"),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ]))
            body.append(tbl3)

    doc.build(body)

# ─────────────────────────────────────────────────────────────────────────────
#  WORKER  (sin whitelist en Lite — siempre lista vacía)
# ─────────────────────────────────────────────────────────────────────────────
class AnalysisWorker(QThread):
    progress = pyqtSignal(str)
    log      = pyqtSignal(str)
    finished = pyqtSignal(object, object, int, int)
    error    = pyqtSignal(str)

    def __init__(self, filepath: str):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            t0 = time.perf_counter()
            self.log.emit(f"Loading  {os.path.basename(self.filepath)}")

            try:
                df = pd.read_csv(self.filepath, sep=None, engine="python", low_memory=False)
            except Exception:
                df = pd.read_csv(self.filepath, sep=",", low_memory=False)

            self.log.emit(f"{len(df):,} rows  ·  {len(df.columns)} columns")
            df.columns = df.columns.str.strip()

            ip_col = next((c for c in df.columns
                           if re.search(r"src|source|attacker|client|remote", c, re.I)), None)
            if ip_col:
                self.log.emit(f"IP column → '{ip_col}'")
                df["IP_Atacante"] = (df[ip_col].astype(str)
                                     .str.extract(r"\b((?:\d{1,3}\.){3}\d{1,3})\b"))
            else:
                self.log.emit("No IP column — scanning all columns")
                df["_row"] = df.fillna("").astype(str).apply(" ".join, axis=1)
                df["IP_Atacante"] = df["_row"].str.extract(
                    r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

            df_ips = df.dropna(subset=["IP_Atacante"]).copy()
            priv = re.compile(
                r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)")
            df_ips = df_ips[~df_ips["IP_Atacante"].str.match(priv)]
            if df_ips.empty:
                self.error.emit("No external attacker IPs found."); return

            # Usuario
            if "Username" in df_ips.columns:
                df_ips["Usuario"] = df_ips["Username"].astype(str)
            elif "_row" in df_ips.columns:
                df_ips["Usuario"] = df_ips["_row"].str.extract(
                    r"User\s+([^\s]+)\s+failed\s+to\s+login", flags=re.I)
            else:
                df_ips["Usuario"] = pd.NA
            df_ips["Usuario"] = (df_ips["Usuario"].fillna("—")
                                 .replace({"": "—", "nan": "—", "N/A": "—"}))

            # Puerto
            pc = next((c for c in df_ips.columns
                       if re.search(r"dst.?port|dport|dest.?port", c, re.I)), None)
            if pc:
                df_ips["Puerto"] = df_ips[pc].astype(str)
            elif "_row" in df_ips.columns:
                df_ips["Puerto"] = df_ips["_row"].str.extract(
                    r"(?:dst|dport)[\s:=]+(\d{1,5})", flags=re.I)
            else:
                df_ips["Puerto"] = "—"
            df_ips["Puerto"] = df_ips["Puerto"].fillna("—")

            # Timestamp
            tc = next((c for c in df_ips.columns
                       if re.search(r"^(time|date|timestamp|fecha)$", c, re.I)), None)
            df_ips["Timestamp"] = (pd.to_datetime(df_ips[tc], errors="coerce")
                                   if tc else pd.NaT)

            # Severidad
            cnt    = df_ips["IP_Atacante"].value_counts()
            mx     = cnt.max() or 1
            ratios = df_ips["IP_Atacante"].map(cnt) / mx
            df_ips["Severidad"] = np.select(
                [ratios > 0.5, ratios > 0.25, ratios > 0.1],
                ["CRITICAL",   "HIGH",        "MEDIUM"],
                default="LOW"
            )

            # Geolocalización con caché
            ips_u  = df_ips["IP_Atacante"].unique().tolist()
            total  = len(ips_u)
            self.log.emit(f"Geolocating {total:,} unique IPs")
            cached  = db_geo_load(ips_u)
            missing = [ip for ip in ips_u if ip not in cached]
            if cached:
                self.log.emit(f"  {len(cached):,} from cache  ·  {len(missing):,} to fetch")
            geo_results: dict = dict(cached)

            if missing:
                batches = [missing[i:i+45] for i in range(0, len(missing), 45)]

                def _fetch_batch(batch):
                    for _ in range(3):
                        try:
                            r = requests.post(
                                "http://ip-api.com/batch",
                                json=[{"query": ip,
                                       "fields": "query,country,lat,lon,status"}
                                      for ip in batch],
                                timeout=15)
                            if r.status_code == 429:
                                time.sleep(65); continue
                            if r.status_code == 200:
                                result = {}
                                for d in r.json():
                                    ip = d.get("query", "")
                                    if d.get("status") == "success":
                                        result[ip] = (d["country"],
                                                      d.get("lat", 0.0),
                                                      d.get("lon", 0.0))
                                    else:
                                        result[ip] = ("Unknown", 0.0, 0.0)
                                db_geo_save(result)
                                return result
                        except Exception:
                            time.sleep(2)
                    return {ip: ("Error", 0.0, 0.0) for ip in batch}

                completed = 0
                with ThreadPoolExecutor(max_workers=min(2, len(batches))) as pool:
                    futures = {}
                    for idx, batch in enumerate(batches):
                        if idx > 0: time.sleep(0.7)
                        futures[pool.submit(_fetch_batch, batch)] = batch
                    for fut in as_completed(futures):
                        geo_results.update(fut.result())
                        completed += len(futures[fut])
                        self.progress.emit(
                            f"Geolocating  {min(completed,len(missing))}/{len(missing)}")

            df_ips["Pais"] = df_ips["IP_Atacante"].map(
                lambda ip: geo_results.get(ip, ("Unknown", 0.0, 0.0))[0])
            df_ips["Lat"]  = df_ips["IP_Atacante"].map(
                lambda ip: geo_results.get(ip, ("Unknown", 0.0, 0.0))[1])
            df_ips["Lon"]  = df_ips["IP_Atacante"].map(
                lambda ip: geo_results.get(ip, ("Unknown", 0.0, 0.0))[2])

            df_mapa = df_ips.groupby("Pais").size().reset_index(name="Total_Ataques")

            cols = [c for c in ["Timestamp","IP_Atacante","Pais","Puerto",
                                 "Usuario","Severidad","Lat","Lon"]
                    if c in df_ips.columns]
            csv_path = Path.home() / "Resultado_KATANA.csv"
            df_ips[cols].to_csv(csv_path, index=False)

            elapsed = time.perf_counter() - t0
            self.log.emit(f"CSV saved  {csv_path}")
            self.log.emit(f"Analysis completed in {elapsed:.1f}s")
            self.finished.emit(df_ips, df_mapa, total, len(df_ips))

        except Exception as e:
            traceback.print_exc(); self.error.emit(str(e))

# ─────────────────────────────────────────────────────────────────────────────
#  COMPONENTES
# ─────────────────────────────────────────────────────────────────────────────
class MetricTile(QWidget):
    def __init__(self, title: str, color_key: str = "ACCENT"):
        super().__init__()
        self._key = color_key
        self.setObjectName("card")
        lo = QVBoxLayout(self); lo.setContentsMargins(16,12,16,12); lo.setSpacing(4)
        self._val = lbl("—", size=26, color=T(color_key), bold=True, mono=True)
        lo.addWidget(self._val)
        lo.addWidget(lbl(title, size=10, dim=True))
        self.setMinimumWidth(100)

    def set(self, v): self._val.setText(str(v))
    def recolor(self):
        self._val.setStyleSheet(
            f"font-size:26px;font-family:{MONO};font-weight:600;"
            f"color:{T(self._key)};background:transparent;")


class StatusDot(QWidget):
    def __init__(self, color: str, size: int = 7):
        super().__init__()
        self._c = color; self._s = size
        self.setFixedSize(size + 2, size + 2)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(self._c)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(1, 1, self._s, self._s)


class FilterRow(QWidget):
    changed = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        lo = QHBoxLayout(self); lo.setContentsMargins(10,6,10,6); lo.setSpacing(8)
        lo.addWidget(lbl("Filter:", size=10, dim=True))
        self.ip      = QLineEdit(); self.ip.setPlaceholderText("IP or range")
        self.ip.setFixedWidth(150); self.ip.textChanged.connect(self._emit)
        self.country = QLineEdit(); self.country.setPlaceholderText("Country")
        self.country.setFixedWidth(110); self.country.textChanged.connect(self._emit)
        self.sev     = QComboBox()
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

# ─────────────────────────────────────────────────────────────────────────────
#  DIÁLOGO EXPORT  (solo PDF en Lite + bloque Enterprise)
# ─────────────────────────────────────────────────────────────────────────────
class ExportDialog(QDialog):
    def __init__(self, df, df_mapa, parent=None):
        super().__init__(parent)
        self.df = df; self.df_mapa = df_mapa
        self.setWindowTitle("Export"); self.setFixedWidth(420)
        lo = QVBoxLayout(self); lo.setContentsMargins(24,24,24,20); lo.setSpacing(14)

        # ── Título ────────────────────────────────────────────────────────────
        lo.addWidget(lbl("Export Report", size=15, bold=True))
        lo.addWidget(sep())

        # ── Sección Lite (disponible) ─────────────────────────────────────────
        avail = QWidget(); avail.setObjectName("card")
        avail_lo = QVBoxLayout(avail)
        avail_lo.setContentsMargins(16,14,16,14); avail_lo.setSpacing(6)

        hdr_a = QHBoxLayout(); hdr_a.setSpacing(8)
        dot_a = StatusDot(T("SUCCESS"), size=8)
        lbl_a = lbl("Available in Lite", size=10, bold=True, color=T("SUCCESS"))
        hdr_a.addWidget(dot_a); hdr_a.addWidget(lbl_a); hdr_a.addStretch()
        avail_lo.addLayout(hdr_a)

        pdf_row = QHBoxLayout(); pdf_row.setSpacing(8)
        pdf_row.addWidget(lbl("✓", size=12, color=T("SUCCESS")))
        pdf_row.addWidget(lbl("PDF  — Executive forensic report", size=11))
        pdf_row.addStretch()
        avail_lo.addLayout(pdf_row)
        lo.addWidget(avail)

        # ── Opciones PDF ──────────────────────────────────────────────────────
        row = QHBoxLayout(); row.setSpacing(6)
        self.chk_top = QCheckBox("Limit to top")
        self.spin    = QSpinBox(); self.spin.setRange(10, 9999); self.spin.setValue(100)
        self.spin.setFixedWidth(70)
        row.addWidget(self.chk_top); row.addWidget(self.spin)
        row.addWidget(lbl("IPs", dim=True)); row.addStretch()
        lo.addLayout(row)

        lo.addWidget(sep())

        # ── Sección Enterprise (bloqueada) ────────────────────────────────────
        locked = QWidget()
        locked.setObjectName("card")
        locked.setStyleSheet(
            f"background:{T('SURFACE')}; border:1px solid {T('WARN')}44;"
            f"border-radius:6px; opacity:0.85;")
        locked_lo = QVBoxLayout(locked)
        locked_lo.setContentsMargins(16,14,16,14); locked_lo.setSpacing(8)

        hdr_l = QHBoxLayout(); hdr_l.setSpacing(8)
        dot_l = StatusDot(T("WARN"), size=8)
        lbl_l = lbl("Enterprise only", size=10, bold=True, color=T("WARN"))
        hdr_l.addWidget(dot_l); hdr_l.addWidget(lbl_l); hdr_l.addStretch()
        locked_lo.addLayout(hdr_l)

        for icon, fmt, desc in [
            ("⊘", "Excel  (.xlsx)", "Full IP table with all fields"),
            ("⊘", "JSON  — SIEM/SOAR", "Machine-readable IOC payload"),
            ("⊘", "IOC List  (.txt)", "Plain IP list for firewalls & SIEM"),
            ("⊘", "3D Globe  (.html)", "Interactive geolocation globe"),
        ]:
            row_e = QHBoxLayout(); row_e.setSpacing(8)
            row_e.addWidget(lbl(icon, size=12, color=T("INK_DIM")))
            row_e.addWidget(lbl(fmt, size=11, color=T("INK_DIM")))
            sep_e = lbl("·", size=11, color=T("INK_DIM"))
            row_e.addWidget(sep_e)
            row_e.addWidget(lbl(desc, size=10, color=T("INK_DIM")))
            row_e.addStretch()
            locked_lo.addLayout(row_e)

        lo.addWidget(locked)

        # ── Botones ───────────────────────────────────────────────────────────
        lo.addWidget(sep())
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setObjectName("primary")
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Export PDF")
        btns.accepted.connect(self._run); btns.rejected.connect(self.reject)
        lo.addWidget(btns)

    def _run(self):
        df = self.df
        if self.chk_top.isChecked():
            top_ips = df["IP_Atacante"].value_counts().head(self.spin.value()).index
            df = df[df["IP_Atacante"].isin(top_ips)]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        p  = f"KATANA_Report_{ts}.pdf"
        try:
            _build_pdf(df, self.df_mapa, p)
            QMessageBox.information(self, "Done", f"PDF saved:\n{os.path.abspath(p)}")
            webbrowser.open(f"file://{os.path.abspath(p)}")
        except Exception as e:
            QMessageBox.critical(self, "PDF Error", str(e))
        self.accept()

# ─────────────────────────────────────────────────────────────────────────────
#  SPLASH SCREEN
# ─────────────────────────────────────────────────────────────────────────────
class SplashScreen(QWidget):
    """Pantalla de carga minimalista con logo SVG pintado a mano y barra de progreso."""
    done = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowFlags(
            Qt.WindowType.SplashScreen |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(420, 260)

        # Centrar en pantalla
        screen = QApplication.primaryScreen().geometry()
        self.move(
            (screen.width()  - self.width())  // 2,
            (screen.height() - self.height()) // 2,
        )

        # Layout principal
        root = QWidget(self)
        root.setFixedSize(420, 260)
        root.setStyleSheet(
            "background:#1C1C1E; border-radius:16px; border:1px solid #3A3A3C;")
        lo = QVBoxLayout(root)
        lo.setContentsMargins(40, 40, 40, 36)
        lo.setSpacing(0)

        # ── Logo (widget personalizado) ──────────────────────────────────────
        logo_row = QHBoxLayout(); logo_row.setSpacing(12)

        class _Logo(QWidget):
            def __init__(self):
                super().__init__()
                self.setFixedSize(44, 44)
            def paintEvent(self, _):
                p = QPainter(self)
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                # Fondo círculo accent
                p.setBrush(QBrush(QColor("#0A84FF")))
                p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(0, 0, 44, 44)
                # Letra K en blanco
                from PyQt6.QtGui import QPainterPath
                p.setBrush(QBrush(QColor("white")))
                f = QFont("Poppins", 20, QFont.Weight.Bold)
                p.setFont(f)
                p.setPen(QColor("white"))
                p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "K")

        logo_row.addWidget(_Logo())
        txt_col = QVBoxLayout(); txt_col.setSpacing(2)
        name_lbl = QLabel("KATANA")
        name_lbl.setStyleSheet(
            f"font-family:{SANS}; font-size:22px; font-weight:800;"
            f"color:#F2F2F7; background:transparent; letter-spacing:2px;")
        ver_lbl = QLabel("Lite  ·  Threat Intelligence Platform")
        ver_lbl.setStyleSheet(
            f"font-family:{SANS}; font-size:11px; font-weight:400;"
            f"color:#636366; background:transparent;")
        txt_col.addWidget(name_lbl); txt_col.addWidget(ver_lbl)
        logo_row.addLayout(txt_col); logo_row.addStretch()
        lo.addLayout(logo_row)
        lo.addSpacing(32)

        # ── Texto de estado ──────────────────────────────────────────────────
        self._status = QLabel("Initializing…")
        self._status.setStyleSheet(
            f"font-family:{SANS}; font-size:11px; font-weight:500;"
            f"color:#AEAEB2; background:transparent;")
        lo.addWidget(self._status)
        lo.addSpacing(10)

        # ── Barra de progreso ────────────────────────────────────────────────
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setFixedHeight(4)
        self._bar.setTextVisible(False)
        self._bar.setStyleSheet(f"""
            QProgressBar {{
                background:#3A3A3C; border:none; border-radius:2px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0A84FF, stop:1 #30D158);
                border-radius:2px;
            }}
        """)
        lo.addWidget(self._bar)
        lo.addSpacing(14)

        # ── Versión y copyright ──────────────────────────────────────────────
        footer = QLabel("v8.0  ·  Sophos Firewall Log Analyzer")
        footer.setStyleSheet(
            f"font-family:{SANS}; font-size:9px; font-weight:400;"
            f"color:#48484A; background:transparent;")
        lo.addWidget(footer)

        # ── Animación de carga ───────────────────────────────────────────────
        self._steps = [
            (15,  "Loading libraries…"),
            (35,  "Initializing database…"),
            (55,  "Applying theme…"),
            (75,  "Building interface…"),
            (92,  "Almost ready…"),
            (100, "Ready."),
        ]
        self._step_idx = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)
        self._timer.start(220)

    def _advance(self):
        if self._step_idx >= len(self._steps):
            self._timer.stop()
            QTimer.singleShot(180, self.done.emit)
            return
        val, msg = self._steps[self._step_idx]
        self._bar.setValue(val)
        self._status.setText(msg)
        self._step_idx += 1

    def paintEvent(self, event):
        """Sombra suave bajo la ventana."""
        super().paintEvent(event)


# ─────────────────────────────────────────────────────────────────────────────
#  VENTANA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
class KatanaLiteApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KATANA Lite  ·  Threat Intelligence Platform")
        self.setMinimumSize(1200, 780)
        self.df     = None
        self.df_map = None
        self._aw    = None
        self._dark  = True
        self.setStyleSheet(_build_qss())
        self._ui()

    # ──────────────────────────────────────────────────────── LAYOUT ──
    def _ui(self):
        root = QWidget(); self.setCentralWidget(root)
        rl = QVBoxLayout(root); rl.setContentsMargins(0,0,0,0); rl.setSpacing(0)
        rl.addWidget(self._build_topbar())

        body = QWidget(); bl = QHBoxLayout(body)
        bl.setContentsMargins(0,0,0,0); bl.setSpacing(0)
        bl.addWidget(self._build_sidebar())

        self._main_w = QWidget()
        self._main_w.setStyleSheet(f"background:{T('BG')};")
        ml = QHBoxLayout(self._main_w)
        ml.setContentsMargins(16,16,16,16); ml.setSpacing(12)
        self._spl = QSplitter(Qt.Orientation.Horizontal)
        self._spl.setStyleSheet(
            f"QSplitter::handle{{background:{T('BORDER')};width:1px;}}")
        self._spl.addWidget(self._build_ip_panel())
        self._spl.addWidget(self._build_tabs())
        self._spl.setSizes([290, 880])
        ml.addWidget(self._spl)
        bl.addWidget(self._main_w, 1)
        rl.addWidget(body, 1)

    # ──────────────────────────────────────────────────────── TOPBAR ──
    def _build_topbar(self):
        bar = QWidget(); bar.setObjectName("topbar"); bar.setFixedHeight(38)
        lo = QHBoxLayout(bar); lo.setContentsMargins(20,0,20,0); lo.setSpacing(16)
        lo.addWidget(StatusDot(T("SUCCESS")))
        lo.addWidget(lbl("KATANA", size=13, bold=True))
        lo.addWidget(lbl("Lite", size=11, color=T("ACCENT")))
        lo.addWidget(sep(vertical=True)); lo.addWidget(spacer(h=4))
        self._tb_file = lbl("No log loaded", size=10, dim=True)
        lo.addWidget(self._tb_file)
        lo.addWidget(spacer())
        self._tb_time = lbl("", size=10, mono=True, dim=True)
        lo.addWidget(self._tb_time)
        self._btn_theme = QPushButton("●  Dark")
        self._btn_theme.setObjectName("theme_btn")
        self._btn_theme.setFixedSize(72, 24)
        self._btn_theme.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_theme.clicked.connect(self._toggle_theme)
        lo.addWidget(self._btn_theme)
        t = QTimer(self)
        t.timeout.connect(
            lambda: self._tb_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S")))
        t.start(1000)
        self._tb_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        return bar

    # ──────────────────────────────────────────────────────── SIDEBAR ──
    def _build_sidebar(self):
        sb = QWidget(); sb.setObjectName("sidebar"); sb.setFixedWidth(210)
        lo = QVBoxLayout(sb); lo.setContentsMargins(16,20,16,16); lo.setSpacing(0)

        lo.addWidget(lbl("Operations", size=10, dim=True)); lo.addSpacing(8)

        self.btn_load = QPushButton("Load CSV log")
        self.btn_load.setFixedHeight(36)
        self.btn_load.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_load.clicked.connect(self._load)
        lo.addWidget(self.btn_load)

        self._file_lbl = lbl("No file selected", size=10, dim=True)
        self._file_lbl.setWordWrap(True)
        lo.addSpacing(6); lo.addWidget(self._file_lbl); lo.addSpacing(10)

        self._pbar = QProgressBar()
        self._pbar.setFixedHeight(2); self._pbar.setRange(0, 0)
        self._pbar.setVisible(False)
        lo.addWidget(self._pbar); lo.addSpacing(6)

        self.btn_run = QPushButton("Run analysis")
        self.btn_run.setObjectName("primary"); self.btn_run.setFixedHeight(38)
        self.btn_run.setEnabled(False)
        self.btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_run.clicked.connect(self._run)
        lo.addWidget(self.btn_run); lo.addSpacing(8)

        self.btn_export = QPushButton("Export PDF")
        self.btn_export.setObjectName("success"); self.btn_export.setFixedHeight(34)
        self.btn_export.setEnabled(False)
        self.btn_export.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_export.clicked.connect(self._export)
        lo.addWidget(self.btn_export)

        lo.addSpacing(20); lo.addWidget(sep()); lo.addSpacing(16)
        lo.addWidget(lbl("Metrics", size=10, dim=True)); lo.addSpacing(8)

        self.m_ips    = MetricTile("Unique IPs",   "ACCENT")
        self.m_events = MetricTile("Total events", "DANGER")
        self.m_ctrs   = MetricTile("Countries",    "WARN")
        self.m_crit   = MetricTile("Critical IPs", "S_CRIT")
        for m in [self.m_ips, self.m_events, self.m_ctrs, self.m_crit]:
            lo.addWidget(m); lo.addSpacing(6)

        lo.addStretch()
        lo.addWidget(lbl("Sophos Firewall Log Analyzer", size=9, dim=True))
        return sb

    # ──────────────────────────────────────────────────────── IP PANEL ──
    def _build_ip_panel(self):
        panel = QWidget(); panel.setObjectName("card")
        lo = QVBoxLayout(panel); lo.setContentsMargins(0,0,0,0); lo.setSpacing(0)

        self._ip_hdr = QWidget(); self._ip_hdr.setFixedHeight(44)
        self._ip_hdr.setStyleSheet(
            f"background:{T('BG')};border-bottom:1px solid {T('BORDER')};")
        hl = QHBoxLayout(self._ip_hdr); hl.setContentsMargins(14,0,10,0)
        hl.addWidget(lbl("Detected IPs", size=11, bold=True))
        hl.addStretch()
        self._ip_count = lbl("0", size=11, mono=True, color=T("ACCENT"))
        hl.addWidget(self._ip_count)
        btn_ctx = QPushButton("···"); btn_ctx.setObjectName("ghost")
        btn_ctx.setFixedSize(28, 28)
        btn_ctx.clicked.connect(self._ip_menu)
        hl.addWidget(btn_ctx)
        lo.addWidget(self._ip_hdr)

        self._filter = FilterRow()
        self._filter.changed.connect(self._filter_table)
        lo.addWidget(self._filter); lo.addWidget(sep())

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

    # ──────────────────────────────────────────────────────── TABS ──
    def _build_tabs(self):
        self.tabs = QTabWidget()
        for name, builder in [
            ("Dashboard",  self._build_tab_dashboard),
            ("Geography",  self._build_tab_geo),
            ("Timeline",   self._build_tab_timeline),
            ("Users",      self._build_tab_users),
            ("Intel Map",  self._build_tab_intel),
            ("History",    self._build_tab_history),
        ]:
            w = QWidget(); self.tabs.addTab(w, name); builder(w)
        return self.tabs

    # ── Dashboard ──────────────────────────────────────────────────────
    def _build_tab_dashboard(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(16)

        kpi_row = QHBoxLayout(); kpi_row.setSpacing(10)
        self._kpi = {}
        for k, title, ck in [("events",   "Events",         "DANGER"),
                               ("ips",      "Unique IPs",     "ACCENT"),
                               ("countries","Countries",      "WARN"),
                               ("critical", "Critical",       "S_CRIT"),
                               ("users",    "Users targeted", "INK2")]:
            tile = MetricTile(title, ck)
            self._kpi[k] = tile; kpi_row.addWidget(tile)
        lo.addLayout(kpi_row)

        charts = QHBoxLayout(); charts.setSpacing(12)
        self._dash_left  = self._chart_panel("Top countries")
        self._dash_right = self._chart_panel("Severity breakdown")
        charts.addWidget(self._dash_left, 1)
        charts.addWidget(self._dash_right, 1)
        lo.addLayout(charts, 1)

        self._dash_status = QLabel("Load a CSV log and run analysis to begin.")
        self._dash_status.setObjectName("card")
        self._dash_status.setStyleSheet("padding:8px 14px;font-size:11px;border-radius:3px;")
        lo.addWidget(self._dash_status)

    def _chart_panel(self, title: str) -> QWidget:
        w = QWidget(); w.setObjectName("card")
        lo = QVBoxLayout(w); lo.setContentsMargins(14,12,14,12); lo.setSpacing(8)
        lo.addWidget(lbl(title, size=11, bold=True))
        inner = QWidget()
        il = QVBoxLayout(inner); il.setContentsMargins(0,0,0,0)
        pl = lbl("No data", dim=True, size=11)
        pl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        il.addWidget(pl)
        lo.addWidget(inner, 1)
        w._inner = inner; w._placeholder = pl
        return w

    def _replace_chart(self, panel, new_widget):
        inner = panel._inner; layout = inner.layout()
        to_rm = []
        for i in range(layout.count()):
            it = layout.itemAt(i)
            w  = it.widget() if it else None
            if w and w is not panel._placeholder:
                to_rm.append(w)
        for w in to_rm:
            layout.removeWidget(w); w.deleteLater()
        panel._placeholder.setVisible(False)
        layout.addWidget(new_widget)

    # ── Geography ──────────────────────────────────────────────────────
    def _build_tab_geo(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20)
        lo.addWidget(lbl("Geographic Distribution", size=13, bold=True))
        lo.addWidget(lbl("Top 15 countries by attack volume", dim=True, size=11))
        lo.addSpacing(10)
        self._geo_inner = QWidget()
        gl = QVBoxLayout(self._geo_inner); gl.setContentsMargins(0,0,0,0)
        self._geo_ph = lbl("Run analysis to see geographic distribution.", dim=True, size=11)
        self._geo_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gl.addWidget(self._geo_ph)
        lo.addWidget(self._geo_inner, 1)

    # ── Timeline ───────────────────────────────────────────────────────
    def _build_tab_timeline(self, tab):
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

    # ── Users ──────────────────────────────────────────────────────────
    def _build_tab_users(self, tab):
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

    # ── Intel Map (solo 2D en Lite) ────────────────────────────────────
    def _build_tab_intel(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(0,0,0,0)
        center = QWidget(); center.setMaximumWidth(440)
        cl = QVBoxLayout(center); cl.setContentsMargins(40,60,40,60); cl.setSpacing(12)
        cl.addWidget(lbl("Threat Map", size=22, bold=True))
        cl.addWidget(lbl("Interactive choropleth map.\nOpens in your browser.",
                         dim=True, size=12))
        cl.addSpacing(20)
        self._btn_map_2d = QPushButton("Open 2D Choropleth Map")
        self._btn_map_2d.setObjectName("primary"); self._btn_map_2d.setFixedHeight(40)
        self._btn_map_2d.setEnabled(False)
        self._btn_map_2d.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_map_2d.clicked.connect(self._map_2d)
        cl.addWidget(self._btn_map_2d)
        cl.addSpacing(8)
        cl.addWidget(lbl("3D Globe and advanced features available in KATANA Enterprise.",
                         dim=True, size=10))
        lo.addStretch(); lo.addWidget(center, 0, Qt.AlignmentFlag.AlignCenter); lo.addStretch()

    # ── History ────────────────────────────────────────────────────────
    def _build_tab_history(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(12)
        lo.addWidget(lbl("Analysis History", size=13, bold=True))
        lo.addWidget(lbl("Persistent across sessions — stored in ~/.katana_lite.db",
                         dim=True, size=10))
        lo.addSpacing(4)

        self._hist_tbl = QTableWidget(0, 5)
        self._hist_tbl.setHorizontalHeaderLabels(
            ["Date / Time","File","IPs","Events","Countries"])
        self._hist_tbl.setAlternatingRowColors(True)
        self._hist_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._hist_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        hv = self._hist_tbl.horizontalHeader()
        hv.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._hist_tbl.setColumnWidth(0, 160)
        hv.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in [2, 3, 4]:
            hv.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
            self._hist_tbl.setColumnWidth(i, 80)
        lo.addWidget(self._hist_tbl, 1)

        btn = QPushButton("Clear history"); btn.setFixedWidth(120)
        btn.clicked.connect(self._clear_history)
        lo.addWidget(btn)

        for row in db_history_load():
            self._hist_tbl_add_row(*row)

    # ────────────────────────────────────────────────────── TEMA ──
    def _toggle_theme(self):
        global _T
        self._dark = not self._dark
        _T = THEMES["dark"] if self._dark else THEMES["light"]
        _update_globals()
        self.setStyleSheet(_build_qss())
        self._btn_theme.setText("●  Dark" if self._dark else "○  Light")

        self._main_w.setStyleSheet(f"background:{T('BG')};")
        self._spl.setStyleSheet(
            f"QSplitter::handle{{background:{T('BORDER')};width:1px;}}")
        self._ip_hdr.setStyleSheet(
            f"background:{T('BG')};border-bottom:1px solid {T('BORDER')};")
        self._ip_count.setStyleSheet(
            f"font-size:11px;font-family:{MONO};color:{T('ACCENT')};background:transparent;")

        for tile in [self.m_ips, self.m_events, self.m_ctrs, self.m_crit]:
            tile.recolor()
        for tile in self._kpi.values():
            tile.recolor()

        if self.df is not None:
            self._draw_dashboard(self.df)
            self._draw_geo(self.df)
            self._draw_timeline()
            self._draw_users(self.df)

    # ────────────────────────────────────────────────────── DRAW ──
    def _draw_table(self, df):
        self.tree.clear()
        cnt = df.groupby(["Pais","IP_Atacante"]).size().reset_index(name="N")
        if "Severidad" in df.columns:
            sm = (df[["IP_Atacante","Severidad"]].drop_duplicates()
                  .set_index("IP_Atacante")["Severidad"])
            cnt["S"] = cnt["IP_Atacante"].map(sm).fillna("LOW")
        else:
            cnt["S"] = "LOW"
        for _, r in cnt.sort_values("N", ascending=False).iterrows():
            c  = SEV_COLOR.get(r["S"], T("INK2"))
            it = QTreeWidgetItem([r["S"], str(r["Pais"]),
                                  str(r["IP_Atacante"]), str(r["N"])])
            it.setForeground(0, QBrush(QColor(c)))
            it.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
            it.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tree.addTopLevelItem(it)
        self._ip_count.setText(str(len(cnt)))

    def _draw_dashboard(self, df):
        top_p  = df["Pais"].value_counts().head(10)
        self._replace_chart(self._dash_left,
                            _pg_bar(top_p.index.tolist(), top_p.values.tolist()))
        if "Severidad" in df.columns:
            sc = df.drop_duplicates("IP_Atacante")["Severidad"].value_counts()
        else:
            sc = pd.Series({"LOW": df["IP_Atacante"].nunique()})
        self._replace_chart(self._dash_right,
                            _pg_donut(list(sc.index), list(sc.values)))

    def _draw_geo(self, df):
        top_p = df["Pais"].value_counts().head(15)
        pw    = _pg_bar(top_p.index.tolist(), top_p.values.tolist(),
                        color_first=_T["ACCENT"])
        lo = self._geo_inner.layout()
        while lo.count():
            it = lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        self._geo_ph.setVisible(False)
        lo.addWidget(pw)

    def _draw_timeline(self):
        if self.df is None: return
        df = self.df
        if "Timestamp" not in df.columns or df["Timestamp"].isna().all():
            self._tl_ph.setVisible(True); return
        gran = self._tl_combo.currentText()
        df_t = df.dropna(subset=["Timestamp"]).copy()
        if gran == "Hourly":  df_t["B"] = df_t["Timestamp"].dt.floor("h")
        elif gran == "Daily": df_t["B"] = df_t["Timestamp"].dt.date
        else:                 df_t["B"] = df_t["Timestamp"].dt.to_period("W").dt.start_time
        serie = df_t.groupby("B").size()
        if serie.empty: self._tl_ph.setVisible(True); return
        pw = _pg_line([str(k) for k in serie.index], serie.values.tolist())
        lo = self._tl_inner.layout()
        while lo.count():
            it = lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        self._tl_ph.setVisible(False)
        lo.addWidget(pw)

    def _draw_users(self, df):
        if "Usuario" not in df.columns:
            self._usr_ph.setVisible(True); return
        top_u = (df[df["Usuario"] != "—"]["Usuario"]
                 .value_counts().head(12).sort_values())
        if top_u.empty:
            self._usr_ph.setVisible(True); return
        pw = _pg_hbar(top_u.index.tolist(), top_u.values.tolist())
        lo = self._usr_inner.layout()
        while lo.count():
            it = lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        self._usr_ph.setVisible(False)
        lo.addWidget(pw)

    # ────────────────────────────────────────────────────── LÓGICA ──
    def _load(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Open Sophos Log", "", "CSV files (*.csv);;All files (*.*)")
        if f:
            self._file = f
            name = os.path.basename(f)
            disp = name if len(name) <= 28 else name[:25] + "..."
            self._file_lbl.setText(disp)
            self._file_lbl.setStyleSheet(
                f"color:{T('ACCENT')};font-size:10px;background:transparent;")
            self._tb_file.setText(name)
            self._tb_file.setStyleSheet(
                f"color:{T('INK2')};font-size:10px;background:transparent;")
            self.btn_run.setEnabled(True)

    def _run(self):
        if not hasattr(self, "_file"): return
        self.btn_run.setEnabled(False); self.btn_run.setText("Analyzing…")
        self._btn_map_2d.setEnabled(False)
        self.btn_export.setEnabled(False)
        self._pbar.setVisible(True)
        self._aw = AnalysisWorker(self._file)
        self._aw.progress.connect(self.btn_run.setText)
        self._aw.log.connect(self._log)
        self._aw.finished.connect(self._on_done)
        self._aw.error.connect(self._on_err)
        self._aw.start()

    def _on_done(self, df, df_map, n_ips, n_events):
        self.df = df; self.df_map = df_map

        crit = (df[df["Severidad"] == "CRITICAL"]["IP_Atacante"].nunique()
                if "Severidad" in df.columns else 0)
        usr  = (df[df["Usuario"] != "—"]["Usuario"].nunique()
                if "Usuario" in df.columns else 0)

        self.m_ips.set(n_ips); self.m_events.set(n_events)
        self.m_ctrs.set(df["Pais"].nunique()); self.m_crit.set(crit)
        for k, v in [("events",n_events), ("ips",n_ips),
                     ("countries",df["Pais"].nunique()),
                     ("critical",crit), ("users",usr)]:
            self._kpi[k].set(v)

        self._draw_table(df)
        self._draw_dashboard(df)
        self._draw_geo(df)
        self._draw_timeline()
        self._draw_users(df)

        self._btn_map_2d.setEnabled(True)
        self.btn_export.setEnabled(True)
        self.btn_run.setEnabled(True); self.btn_run.setText("Run analysis")
        self._pbar.setVisible(False)

        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        db_history_add(ts, os.path.basename(self._file),
                       n_ips, n_events, df["Pais"].nunique())
        self._hist_tbl_add_row(ts, os.path.basename(self._file),
                               n_ips, n_events, df["Pais"].nunique())

        self._dash_status.setText(
            f"Analysis complete  ·  {n_ips:,} unique IPs  ·  "
            f"{n_events:,} events  ·  {df['Pais'].nunique()} countries")

        QMessageBox.information(self, "KATANA Lite",
            f"Analysis complete.\n\n"
            f"  {n_ips:,} unique attacker IPs\n"
            f"  {n_events:,} total events\n"
            f"  {df['Pais'].nunique()} countries of origin")

    def _on_err(self, msg):
        self.btn_run.setEnabled(True); self.btn_run.setText("Run analysis")
        self._pbar.setVisible(False)
        QMessageBox.critical(self, "Analysis Error", msg)

    # ────────────────────────────────────────────────────── MAP 2D ──
    def _map_2d(self):
        if self.df_map is None or (hasattr(self.df_map,"empty") and self.df_map.empty):
            return
        import plotly.express as px
        fig = px.choropleth(
            self.df_map, locations="Pais", locationmode="country names",
            color="Total_Ataques", hover_name="Pais",
            color_continuous_scale="Blues",
            title="KATANA Lite  ·  Global Attack Distribution")
        fig.update_layout(
            paper_bgcolor="#1C1C1E", plot_bgcolor="#1C1C1E",
            font=dict(family="IBM Plex Sans,sans-serif", color="#F2F2F7"),
            geo=dict(showframe=False, showcoastlines=True,
                     coastlinecolor="#48484A", bgcolor="#2C2C2E",
                     projection_type="equirectangular"))
        p = os.path.abspath("katana_map.html")
        fig.write_html(p); webbrowser.open(f"file://{p}")

    # ────────────────────────────────────────────────────── FILTER ──
    def _filter_table(self, ip_f, country_f, sev_f):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            it   = root.child(i)
            show = True
            if ip_f      and ip_f.lower()      not in it.text(2).lower(): show = False
            if country_f and country_f.lower() not in it.text(1).lower(): show = False
            if sev_f != "All" and it.text(0) != sev_f:                    show = False
            it.setHidden(not show)

    # ────────────────────────────────────────────────────── MENUS ──
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
        m.addAction(f"Copy  {ip}",
                    lambda: QApplication.clipboard().setText(ip))
        m.addSeparator()
        m.addAction("VirusTotal  ↗",
                    lambda: webbrowser.open(
                        f"https://www.virustotal.com/gui/ip-address/{ip}"))
        m.addAction("AbuseIPDB  ↗",
                    lambda: webbrowser.open(f"https://www.abuseipdb.com/check/{ip}"))
        m.addAction("Shodan  ↗",
                    lambda: webbrowser.open(f"https://www.shodan.io/host/{ip}"))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _copy_all_ips(self):
        if self.df is None: return
        QApplication.clipboard().setText("\n".join(self.df["IP_Atacante"].unique()))

    def _export_visible_ioc(self):
        root = self.tree.invisibleRootItem()
        ips  = [root.child(i).text(2) for i in range(root.childCount())
                if not root.child(i).isHidden()]
        p = f"IOC_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"# KATANA Lite IOC  {datetime.now()}\n"); f.write("\n".join(ips))
        QMessageBox.information(self, "Exported", f"{len(ips)} IPs → {p}")

    # ────────────────────────────────────────────────────── EXPORT ──
    def _export(self):
        if self.df is None: return
        ExportDialog(self.df, self.df_map, self).exec()

    # ────────────────────────────────────────────────────── HISTORY ──
    def _hist_tbl_add_row(self, ts, filename, n_ips, n_events, n_ctrs):
        self._hist_tbl.insertRow(0)
        for c, v in enumerate([ts, filename, str(n_ips), str(n_events), str(n_ctrs)]):
            it = QTableWidgetItem(v)
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._hist_tbl.setItem(0, c, it)

    def _clear_history(self):
        db_history_clear(); self._hist_tbl.setRowCount(0)

    # ────────────────────────────────────────────────────── LOG ──
    def _log(self, text):
        # Lite no tiene consola visible — solo barra de progreso
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    splash = SplashScreen()
    splash.show()
    app.processEvents()

    _main_win = None

    def _launch():
        global _main_win
        splash.hide()
        _main_win = KatanaLiteApp()
        _main_win.show()
        splash.deleteLater()

    splash.done.connect(_launch)
    sys.exit(app.exec())