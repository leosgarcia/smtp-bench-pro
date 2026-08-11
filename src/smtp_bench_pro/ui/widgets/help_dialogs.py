"""Small institutional dialogs used by SMTP Bench Pro UI."""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QTextEdit, QVBoxLayout


class LicenseDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Licença")
        self.setMinimumSize(520, 360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        title = QLabel("SMTP Bench Pro")
        title.setStyleSheet("font-size: 15pt; font-weight: 700;")
        layout.addWidget(title)

        subtitle = QLabel("Software Livre sob os termos da Licença MIT.")
        subtitle.setStyleSheet("color: #B8C0CC;")
        layout.addWidget(subtitle)

        body = QTextEdit()
        body.setReadOnly(True)
        body.setPlainText(
            "MIT License\n\n"
            "Copyright (c) 2026 WL Tech\n\n"
            "Permission is hereby granted, free of charge, to any person obtaining a copy \n"
            "of this software and associated documentation files (the 'Software'), to deal \n"
            "in the Software without restriction, including without limitation the rights \n"
            "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell \n"
            "copies of the Software, and to permit persons to whom the Software is \n"
            "furnished to do so, subject to the following conditions: ..."
        )
        layout.addWidget(body, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.StandardButton.Close).clicked.connect(self.accept)
        layout.addWidget(buttons)
