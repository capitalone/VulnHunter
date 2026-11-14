"""API Connector tab for VulnHunter (PyQt5).

Pick a provider, paste an API key, press Connect. The key is verified with a
tiny test request; on success the tab reports "Connected" and tells the rest
of the app. Keys are kept in memory for the session only, never written to disk.
"""
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QVBoxLayout, QWidget,
)

PROVIDERS = {
    "claude": {"label": "Claude (Anthropic)", "base_url": "",
               "model_id": "claude-sonnet-5-5", "auth_mode": ""},
    "deepseek": {"label": "DeepSeek", "base_url": "https://api.deepseek.com/anthropic",
                 "model_id": "deepseek-chat", "auth_mode": "deepseek"},
    "gemini": {"label": "Gemini (Google)", "base_url": "",
               "model_id": "gemini-2.5-flash", "auth_mode": ""},
}

GREEN, RED, BLUE, MUTED = "#4ADE80", "#F87171", "#38BDF8", "#7F93AD"


class ConnectWorker(QThread):
    """Verifies credentials with a 1-token request, off the UI thread."""
    done = pyqtSignal(bool, str)

    def __init__(self, provider, cfg):
        super().__init__()
        self.provider = provider
        self.cfg = cfg

    def run(self):
        try:
            if not self.cfg.get("api_key"):
                raise ValueError("Enter an API key first.")
            if not self.cfg.get("model_id"):
                raise ValueError("Enter a model ID.")
            if self.provider in ("claude", "deepseek"):
                import anthropic  # pip install anthropic
                kwargs = {"api_key": self.cfg["api_key"]}
                if self.cfg.get("base_url"):
                    kwargs["base_url"] = self.cfg["base_url"]
                reply = anthropic.Anthropic(**kwargs).messages.create(
                    model=self.cfg["model_id"], max_tokens=8,
                    messages=[{"role": "user", "content": "ping"}])
                self.done.emit(True, f"Model: {reply.model}")
            else:
                from google import genai  # pip install google-genai
                genai.Client(api_key=self.cfg["api_key"]).models.generate_content(
                    model=self.cfg["model_id"], contents="ping")
                self.done.emit(True, f"Model: {self.cfg['model_id']}")
        except ImportError as e:
            self.done.emit(False, f"Missing package '{e.name}'. Install it with pip, then retry.")
        except Exception as e:
            self.done.emit(False, str(e))


class ApiConnectorPage(QWidget):
    connected = pyqtSignal(str, str)  # provider key, display label
    disconnected = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.settings = {k: {"api_key": "", "base_url": p["base_url"],
                             "model_id": p["model_id"], "auth_mode": p["auth_mode"]}
                         for k, p in PROVIDERS.items()}
        self._current = "claude"
        self.connected_provider = None
        self._worker = None

        title = QLabel("API Connector")
        title.setObjectName("title")
        subtitle = QLabel("Connect VulnHunter to an AI model with your own API key.")
        subtitle.setStyleSheet(f"color: {MUTED};")

        self.provider_box = QComboBox()
        for key, p in PROVIDERS.items():
            self.provider_box.addItem(p["label"], key)
        self.provider_box.currentIndexChanged.connect(self._on_provider_changed)

        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.Password)
        self.api_key.setPlaceholderText("Paste your API key")
        self.api_key.returnPressed.connect(self.connect_clicked)
        self.show_key = QCheckBox("Show")
        self.show_key.toggled.connect(
            lambda on: self.api_key.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        key_row = QHBoxLayout()
        key_row.addWidget(self.api_key, 1)
        key_row.addWidget(self.show_key)

        self.model_id = QLineEdit()
        self.base_url = QLineEdit()
        self.base_url.setPlaceholderText("Leave blank for the provider default")
        self.auth_mode = QLineEdit()
        self.auth_label = QLabel("Auth mode")

        # Advanced fields stay hidden until asked for.
        self.advanced_toggle = QCheckBox("Advanced settings")
        self.advanced_toggle.toggled.connect(self._apply_advanced_visibility)
        self.base_label = QLabel("Base URL")

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(12)
        form.addRow("Provider", self.provider_box)
        form.addRow("API key", key_row)
        form.addRow("Model ID", self.model_id)
        form.addRow(self.base_label, self.base_url)
        form.addRow(self.auth_label, self.auth_mode)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setObjectName("primary")
        self.connect_btn.clicked.connect(self.connect_clicked)
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_clicked)
        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        buttons.addWidget(self.connect_btn)
        buttons.addWidget(self.disconnect_btn)
        buttons.addStretch()

        self.status = QLabel("")
        self.status.setWordWrap(True)
        note = QLabel("Your key stays in memory for this session only and is never saved to disk.")
        note.setStyleSheet(f"color: {MUTED}; font-size: 12px;")

        card = QFrame()
        card.setObjectName("card")
        card.setMaximumWidth(640)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 20, 20, 20)
        cl.setSpacing(16)
        heading = QLabel("Connection")
        heading.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        cl.addWidget(heading)
        cl.addLayout(form)
        cl.addWidget(self.advanced_toggle)
        cl.addLayout(buttons)
        cl.addWidget(self.status)
        cl.addWidget(note)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(card)
        layout.addStretch()

        self._load_form("claude")
        self._refresh_state()

    # ---- form <-> settings
    def _form_values(self):
        return {"api_key": self.api_key.text().strip(), "base_url": self.base_url.text().strip(),
                "model_id": self.model_id.text().strip(), "auth_mode": self.auth_mode.text().strip()}

    def _load_form(self, provider):
        cfg = self.settings[provider]
        self.api_key.setText(cfg["api_key"])
        self.base_url.setText(cfg["base_url"])
        self.model_id.setText(cfg["model_id"])
        self.auth_mode.setText(cfg["auth_mode"])
        self._apply_advanced_visibility()

    def _apply_advanced_visibility(self):
        show = self.advanced_toggle.isChecked()
        for w in (self.base_label, self.base_url):
            w.setVisible(show)
        show_auth = show and self._current == "deepseek"
        for w in (self.auth_label, self.auth_mode):
            w.setVisible(show_auth)

    def _on_provider_changed(self):
        self.settings[self._current] = self._form_values()
        self._current = self.provider_box.currentData()
        self._load_form(self._current)
        self._refresh_state()

    # ---- status
    def _say(self, text, color=None):
        self.status.setStyleSheet(f"color: {color};" if color else "")
        self.status.setText(text)

    def _refresh_state(self):
        is_connected = self.connected_provider == self._current
        self.disconnect_btn.setEnabled(is_connected)
        self.connect_btn.setText("Reconnect" if is_connected else "Connect")
        if is_connected:
            self._say(f"● Connected to {PROVIDERS[self._current]['label']}", GREEN)
        elif self.connected_provider:
            self._say(f"Currently connected to {PROVIDERS[self.connected_provider]['label']}. "
                      f"Press Connect to switch to {PROVIDERS[self._current]['label']}.", MUTED)
        else:
            self._say("Not connected.", MUTED)

    # ---- actions
    def connect_clicked(self):
        if self._worker and self._worker.isRunning():
            return
        self.settings[self._current] = self._form_values()
        self.connect_btn.setEnabled(False)
        self._say("Connecting...", BLUE)
        self._worker = ConnectWorker(self._current, dict(self.settings[self._current]))
        self._worker.done.connect(self._on_connect_done)
        self._worker.start()

    def _on_connect_done(self, ok, message):
        self.connect_btn.setEnabled(True)
        if ok:
            self.connected_provider = self._current
            self._refresh_state()
            self.status.setText(self.status.text() + f"   ({message})")
            self.connected.emit(self._current, PROVIDERS[self._current]["label"])
        else:
            self._say(f"Could not connect: {message}", RED)

    def disconnect_clicked(self):
        self.settings[self._current]["api_key"] = ""
        self.api_key.clear()
        if self.connected_provider == self._current:
            self.connected_provider = None
            self.disconnected.emit()
        self._refresh_state()

    # ---- used by the scan page
    def get_settings(self, provider):
        """Saved settings for 'claude', 'deepseek' or 'gemini' (includes unsaved edits on screen)."""
        if provider == self._current:
            self.settings[provider] = self._form_values()
        return dict(self.settings.get(provider, {}))