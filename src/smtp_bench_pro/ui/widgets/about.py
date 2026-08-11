"""Widget institucional da aba "Sobre" do SMTP Bench Pro."""

from __future__ import annotations

import platform
import sqlite3
import sys

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import QApplication, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget, QStyle

from smtp_bench_pro.paths import APP_NAME, APP_REPOSITORY, APP_TAGLINE, APP_WEBSITE, VENDOR_NAME
from smtp_bench_pro.ui.widgets.help_dialogs import LicenseDialog
from smtp_bench_pro.version import __version__


class AboutWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 14, 18, 14)
        main_layout.setSpacing(10)

        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        icon_label = QLabel()
        icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        icon_label.setPixmap(icon.pixmap(40, 40))
        header_layout.addWidget(icon_label)

        title_box = QVBoxLayout()
        title_lbl = QLabel(APP_NAME)
        font_title = QFont()
        font_title.setPointSize(15)
        font_title.setBold(True)
        title_lbl.setFont(font_title)

        subtitle_lbl = QLabel(APP_TAGLINE)
        subtitle_lbl.setStyleSheet("color: #8aa4c8; font-size: 10pt;")

        meta_lbl = QLabel(f"Version {__version__} | © 2026 {VENDOR_NAME} | MIT License")
        meta_lbl.setStyleSheet("color: #38bdf8; font-size: 9pt; margin-top: 1px;")

        title_box.addWidget(title_lbl)
        title_box.addWidget(subtitle_lbl)
        title_box.addWidget(meta_lbl)

        header_layout.addLayout(title_box)
        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        links_layout = QHBoxLayout()
        links_layout.setSpacing(8)

        btn_site = QPushButton("WL Tech")
        btn_site.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(APP_WEBSITE)))

        btn_repo = QPushButton("GitHub")
        btn_repo.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(APP_REPOSITORY)))

        btn_doc = QPushButton("Documentação")
        btn_doc.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(f"{APP_REPOSITORY}#readme")))

        btn_issues = QPushButton("Suporte")
        btn_issues.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(f"{APP_REPOSITORY}/issues/new/choose")))

        for btn in (btn_site, btn_repo, btn_doc, btn_issues):
            links_layout.addWidget(btn)
        links_layout.addStretch()
        main_layout.addLayout(links_layout)

        about_group = QGroupBox("Produto")
        about_layout = QVBoxLayout(about_group)
        about_layout.setContentsMargins(10, 12, 10, 10)
        about_desc = QLabel(
            f"O <b>{APP_NAME}</b> é uma ferramenta desktop profissional desenvolvida para benchmark, "
            "diagnóstico SMTP, análise de postura TLS/certificado e diagnóstico estático de DNS de e-mail. "
            "Inclui histórico auditável, exportação JSON/HTML e integração com o Bench Pro Core via Integration API v1."
        )
        about_desc.setWordWrap(True)
        about_desc.setStyleSheet("font-size: 9.5pt; line-height: 1.3;")
        about_layout.addWidget(about_desc)
        main_layout.addWidget(about_group)

        env_group = QGroupBox("Ambiente")
        env_layout = QVBoxLayout(env_group)
        env_layout.setContentsMargins(10, 12, 10, 10)

        py_ver = f"Python {sys.version.split()[0]}"
        try:
            import PySide6.QtCore
            qt_ver = f"PySide6 {PySide6.QtCore.__version__}"
        except Exception:
            qt_ver = "PySide6 / Qt 6.x"

        sqlite_ver = f"SQLite {sqlite3.sqlite_version}"
        os_ver = f"{platform.system()} {platform.release()}"
        arch_ver = platform.machine()

        self.sys_info_str = (
            f"{APP_NAME} {__version__}\n"
            f"Python: {py_ver}\n"
            f"PySide6: {qt_ver}\n"
            f"SQLite: {sqlite_ver}\n"
            f"Sistema: {os_ver}\n"
            f"Arquitetura: {arch_ver}\n"
            f"Integration API: 1\n"
            f"Schema SQLite: 4"
        )

        grid_info_layout = QHBoxLayout()
        grid_info_layout.setSpacing(18)

        def make_pill(title: str, value: str):
            col = QVBoxLayout()
            t = QLabel(title)
            t.setStyleSheet("color: #8aa4c8; font-size: 8pt; font-weight: bold;")
            v = QLabel(value)
            v.setStyleSheet("font-weight: bold; font-size: 9pt;")
            col.addWidget(t)
            col.addWidget(v)
            return col

        grid_info_layout.addLayout(make_pill("PYTHON", py_ver))
        grid_info_layout.addLayout(make_pill("INTERFACE QT", qt_ver))
        grid_info_layout.addLayout(make_pill("BANCO SQLITE", sqlite_ver))
        grid_info_layout.addLayout(make_pill("SISTEMA", os_ver))
        grid_info_layout.addLayout(make_pill("ARQUITETURA", arch_ver))
        grid_info_layout.addStretch()

        btn_copy = QPushButton("Copiar ambiente")
        btn_copy.clicked.connect(self._copy_system_info)
        grid_info_layout.addWidget(btn_copy)

        env_layout.addLayout(grid_info_layout)
        main_layout.addWidget(env_group)

        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(12)

        credits_group = QGroupBox("Créditos")
        credits_box = QVBoxLayout(credits_group)
        credits_box.setContentsMargins(10, 12, 10, 10)
        credits_lbl = QLabel(
            f"<b>Produto:</b> {APP_NAME}<br/>"
            f"<b>Vendor:</b> {VENDOR_NAME}<br/>"
            "<b>Desenvolvimento:</b> WL Tech<br/>"
            "<b>Tecnologias:</b> Python 3.11+, PySide6 (Qt), dnspython, tldextract, SQLite<br/>"
            "<b>Capacidades:</b> benchmark, diagnostics, history, security_audit, mail_dns"
        )
        credits_lbl.setTextFormat(Qt.TextFormat.RichText)
        credits_lbl.setStyleSheet("font-size: 9pt;")
        credits_box.addWidget(credits_lbl)
        bottom_layout.addWidget(credits_group, 2)

        license_group = QGroupBox("Licenciamento")
        license_box = QVBoxLayout(license_group)
        license_box.setContentsMargins(10, 12, 10, 10)
        license_lbl = QLabel("Software Livre sob os termos da <b>Licença MIT</b>.")
        license_lbl.setStyleSheet("font-size: 9pt;")
        btn_view_license = QPushButton("Ver Licença")
        btn_view_license.clicked.connect(self._open_license_dialog)
        license_box.addWidget(license_lbl)
        license_box.addWidget(btn_view_license)
        bottom_layout.addWidget(license_group, 1)

        main_layout.addLayout(bottom_layout)
        main_layout.addStretch()

    def _copy_system_info(self) -> None:
        QApplication.clipboard().setText(self.sys_info_str)

    def _open_license_dialog(self) -> None:
        dlg = LicenseDialog(self)
        dlg.exec()
