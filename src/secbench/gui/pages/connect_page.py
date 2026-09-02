"""Connect page: select auth method, sign in, list subscriptions, choose macOS target."""

from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...auth import AuthMethod, AuthManager
from ...auth.base import CredentialBundle

if TYPE_CHECKING:
    from ..main_window import MainWindow

log = logging.getLogger(__name__)


class _SignInWorker(QThread):
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, manager: AuthManager) -> None:
        super().__init__()
        self.manager = manager

    def run(self) -> None:  # noqa: D401 - Qt API
        try:
            bundle = self.manager.sign_in()
            self.finished_ok.emit(bundle)
        except Exception as exc:
            self.failed.emit(str(exc))


class _SubsWorker(QThread):
    finished_ok = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, manager: AuthManager) -> None:
        super().__init__()
        self.manager = manager

    def run(self) -> None:  # noqa: D401
        try:
            subs = self.manager.list_subscriptions()
            self.finished_ok.emit(subs)
        except Exception as exc:
            self.failed.emit(str(exc))


class ConnectPage(QWidget):
    def __init__(self, main: "MainWindow") -> None:
        super().__init__()
        self.main = main
        self._build_ui()
        self._sign_in_worker: _SignInWorker | None = None
        self._subs_worker: _SubsWorker | None = None

    def _build_ui(self) -> None:
        # Top-level layout hosts a QTabWidget with two tabs:
        #   - Cloud (Azure / M365)
        #   - Infrastructure (macOS / Linux)
        outermost = QVBoxLayout(self)
        outermost.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget(self)
        outermost.addWidget(self.tabs)

        # ---- Cloud tab (Azure / M365) -----------------------------------
        cloud_scroll = QScrollArea()
        cloud_scroll.setWidgetResizable(True)
        cloud_host = QWidget()
        cloud_scroll.setWidget(cloud_host)
        outer = QVBoxLayout(cloud_host)
        outer.setContentsMargins(24, 24, 24, 24)
        self.tabs.addTab(cloud_scroll, "Cloud (Azure / M365)")

        title = QLabel("<h2>Connect to Azure / Microsoft 365</h2>")
        outer.addWidget(title)

        # Auth method selection.
        method_box = QGroupBox("Authentication method")
        mb_layout = QHBoxLayout(method_box)
        self.r_interactive = QRadioButton("Interactive browser")
        self.r_device = QRadioButton("Device code")
        self.r_sp = QRadioButton("Service principal")
        self.r_interactive.setChecked(self.main.settings.last_auth_method == "interactive")
        self.r_device.setChecked(self.main.settings.last_auth_method == "device_code")
        self.r_sp.setChecked(self.main.settings.last_auth_method.startswith("sp_"))
        if not (self.r_interactive.isChecked() or self.r_device.isChecked() or self.r_sp.isChecked()):
            self.r_interactive.setChecked(True)
        for r in (self.r_interactive, self.r_device, self.r_sp):
            mb_layout.addWidget(r)
            r.toggled.connect(self._on_method_toggled)
        outer.addWidget(method_box)

        # Common fields.
        common = QGroupBox("Tenant")
        cf = QFormLayout(common)
        self.tenant_edit = QLineEdit(self.main.settings.last_tenant_id)
        self.tenant_edit.setPlaceholderText("organizations or tenant GUID/domain")
        self.client_edit = QLineEdit(self.main.settings.last_client_id)
        self.client_edit.setPlaceholderText("optional client/app id")
        cf.addRow("Tenant ID", self.tenant_edit)
        cf.addRow("Client ID", self.client_edit)
        outer.addWidget(common)

        # Service principal extras.
        self.sp_box = QGroupBox("Service principal credentials")
        sp_layout = QFormLayout(self.sp_box)
        self.secret_edit = QLineEdit()
        self.secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_edit.setPlaceholderText("client secret (or leave blank when using cert)")
        self.cert_edit = QLineEdit()
        self.cert_edit.setPlaceholderText("path to PEM/PFX certificate (optional)")
        self.cert_pass_edit = QLineEdit()
        self.cert_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        sp_layout.addRow("Client secret", self.secret_edit)
        sp_layout.addRow("Certificate path", self.cert_edit)
        sp_layout.addRow("Certificate password", self.cert_pass_edit)
        outer.addWidget(self.sp_box)
        self.sp_box.setVisible(self.r_sp.isChecked())

        # Sign-in row.
        button_row = QHBoxLayout()
        self.sign_in_btn = QPushButton("Sign in")
        self.sign_in_btn.setDefault(True)
        self.sign_in_btn.clicked.connect(self._on_sign_in)
        self.sign_out_btn = QPushButton("Sign out")
        self.sign_out_btn.setEnabled(False)
        self.sign_out_btn.clicked.connect(self._on_sign_out)
        button_row.addWidget(self.sign_in_btn)
        button_row.addWidget(self.sign_out_btn)
        button_row.addStretch(1)
        outer.addLayout(button_row)

        # Subscriptions list (checkboxes; select all by default).
        subs_header = QHBoxLayout()
        subs_header.addWidget(QLabel("<b>Subscriptions to evaluate</b> (tick the boxes)"))
        subs_header.addStretch(1)
        self.select_all_btn = QPushButton("Select all")
        self.select_all_btn.clicked.connect(lambda: self._set_all_checked(True))
        self.select_none_btn = QPushButton("Select none")
        self.select_none_btn.clicked.connect(lambda: self._set_all_checked(False))
        self.refresh_subs_btn = QPushButton("Refresh")
        self.refresh_subs_btn.clicked.connect(self._fetch_subscriptions)
        subs_header.addWidget(self.select_all_btn)
        subs_header.addWidget(self.select_none_btn)
        subs_header.addWidget(self.refresh_subs_btn)
        outer.addLayout(subs_header)

        self.subs_list = QListWidget()
        # We use per-item checkboxes (ItemIsUserCheckable) instead of the
        # row-level MultiSelection so the user can clearly see which
        # subscriptions will be evaluated.
        outer.addWidget(self.subs_list, 1)
        self.subs_count_label = QLabel("0 selected")
        outer.addWidget(self.subs_count_label)
        self.subs_list.itemChanged.connect(self._on_sub_item_changed)

        # Status messages.
        self.status_label = QLabel("")
        outer.addWidget(self.status_label)
        outer.addStretch(1)

        # ---- Infrastructure tab (macOS / Linux / Windows) ---------------
        infra_scroll = QScrollArea()
        infra_scroll.setWidgetResizable(True)
        infra_host = QWidget()
        infra_scroll.setWidget(infra_host)
        infra_outer = QVBoxLayout(infra_host)
        infra_outer.setContentsMargins(24, 24, 24, 24)
        self.tabs.addTab(infra_scroll, "Infrastructure (macOS / Linux / Windows)")

        infra_outer.addWidget(QLabel(
            "<h2>Local OS target (for macOS, RHEL and Windows benchmarks)</h2>"
        ))
        infra_outer.addWidget(QLabel(
            "<p style='color:#555'>Configure the operating system target used by "
            "the macOS Tahoe, Red Hat Enterprise Linux, and Microsoft Windows / "
            "Defender benchmarks. Cloud benchmarks (Azure / M365) do not use "
            "this target.</p>"
        ))

        self.target_box = QGroupBox("Run OS checks against")
        tgt_layout = QVBoxLayout(self.target_box)

        radios = QHBoxLayout()
        sysname = platform.system()
        is_local_supported = sysname in ("Darwin", "Linux", "Windows")
        self.r_local = QRadioButton(f"Local computer (this {sysname or 'host'})")
        self.r_ssh = QRadioButton("Remote macOS / Linux / Windows host (SSH)")
        if not is_local_supported:
            self.r_local.setEnabled(False)
            self.r_local.setToolTip(
                "Local mode is available only when this app runs on macOS, "
                "Linux, or Windows."
            )
        # Apply persisted choice. Use either the new os_target_kind setting or
        # fall back to the legacy macos_target_kind.
        kind = getattr(self.main.settings, "os_target_kind", None) \
            or getattr(self.main.settings, "macos_target_kind", "local")
        if kind == "ssh" or not is_local_supported:
            self.r_ssh.setChecked(True)
        else:
            self.r_local.setChecked(True)
        self.r_local.toggled.connect(self._on_target_toggled)
        self.r_ssh.toggled.connect(self._on_target_toggled)
        radios.addWidget(self.r_local)
        radios.addWidget(self.r_ssh)
        radios.addStretch(1)
        tgt_layout.addLayout(radios)

        # SSH details form
        self.ssh_form_box = QGroupBox("SSH connection")
        ssh_form = QFormLayout(self.ssh_form_box)
        self.ssh_host_edit = QLineEdit(self.main.settings.macos_ssh_host)
        self.ssh_host_edit.setPlaceholderText("hostname or IP address")
        self.ssh_port_spin = QSpinBox()
        self.ssh_port_spin.setRange(1, 65535)
        self.ssh_port_spin.setValue(self.main.settings.macos_ssh_port or 22)
        self.ssh_user_edit = QLineEdit(self.main.settings.macos_ssh_user)
        self.ssh_user_edit.setPlaceholderText("admin user with sudo rights")
        self.ssh_key_edit = QLineEdit(self.main.settings.macos_ssh_key_path)
        self.ssh_key_edit.setPlaceholderText("path to private key (e.g. ~/.ssh/id_ed25519)")
        self.ssh_password_edit = QLineEdit()
        self.ssh_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssh_password_edit.setPlaceholderText("(optional) used only if no key works")
        self.ssh_sudo_chk = QCheckBox("Run privileged commands via sudo on the target")
        self.ssh_sudo_chk.setChecked(self.main.settings.macos_ssh_use_sudo)
        self.ssh_sudo_password_edit = QLineEdit()
        self.ssh_sudo_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssh_sudo_password_edit.setPlaceholderText("(optional) sudo password")

        ssh_form.addRow("Host", self.ssh_host_edit)
        ssh_form.addRow("Port", self.ssh_port_spin)
        ssh_form.addRow("Username", self.ssh_user_edit)
        ssh_form.addRow("Private key", self.ssh_key_edit)
        ssh_form.addRow("Password", self.ssh_password_edit)
        ssh_form.addRow(self.ssh_sudo_chk)
        ssh_form.addRow("Sudo password", self.ssh_sudo_password_edit)

        tgt_layout.addWidget(self.ssh_form_box)

        test_row = QHBoxLayout()
        self.test_target_btn = QPushButton("Test target")
        self.test_target_btn.clicked.connect(self._on_test_target)
        self.target_status = QLabel("")
        test_row.addWidget(self.test_target_btn)
        test_row.addWidget(self.target_status, 1)
        tgt_layout.addLayout(test_row)

        infra_outer.addWidget(self.target_box)
        infra_outer.addStretch(1)
        self._on_target_toggled()

    def _set_all_checked(self, checked: bool) -> None:
        from PyQt6.QtCore import Qt
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self.subs_list.blockSignals(True)
        try:
            for i in range(self.subs_list.count()):
                item = self.subs_list.item(i)
                if item is None:
                    continue
                if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                    item.setCheckState(state)
        finally:
            self.subs_list.blockSignals(False)
        self._update_subs_count()

    def _on_sub_item_changed(self, _item) -> None:
        self._update_subs_count()

    def _update_subs_count(self) -> None:
        from PyQt6.QtCore import Qt
        n = len(self.selected_subscription_ids())
        total = 0
        for i in range(self.subs_list.count()):
            it = self.subs_list.item(i)
            if it is not None and (it.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                total += 1
        self.subs_count_label.setText(f"{n} of {total} subscription(s) selected")

    def _on_method_toggled(self) -> None:
        self.sp_box.setVisible(self.r_sp.isChecked())

    def _selected_method(self) -> AuthMethod:
        if self.r_interactive.isChecked():
            return AuthMethod.INTERACTIVE
        if self.r_device.isChecked():
            return AuthMethod.DEVICE_CODE
        if self.cert_edit.text().strip():
            return AuthMethod.SERVICE_PRINCIPAL_CERT
        return AuthMethod.SERVICE_PRINCIPAL_SECRET

    # ----------------------------------------------------------- handlers
    def _on_sign_in(self) -> None:
        method = self._selected_method()
        try:
            self.main.auth.configure(
                method,
                tenant_id=self.tenant_edit.text().strip() or None,
                client_id=self.client_edit.text().strip() or None,
                client_secret=self.secret_edit.text() or None,
                certificate_path=self.cert_edit.text().strip() or None,
                certificate_password=self.cert_pass_edit.text() or None,
                prompt_callback=self._device_prompt,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Auth configuration", str(exc))
            return

        self.status_label.setText("Signing in...")
        self.sign_in_btn.setEnabled(False)
        self._sign_in_worker = _SignInWorker(self.main.auth)
        self._sign_in_worker.finished_ok.connect(self._on_sign_in_ok)
        self._sign_in_worker.failed.connect(self._on_sign_in_failed)
        self._sign_in_worker.start()

    def _device_prompt(self, verification_uri: str, user_code: str, expires_on: str) -> None:
        QMessageBox.information(
            self,
            "Device code",
            f"Go to {verification_uri} and enter the code:\n\n{user_code}\n\n(expires {expires_on})",
        )

    def _on_sign_in_ok(self, bundle: CredentialBundle) -> None:
        self.sign_in_btn.setEnabled(True)
        self.sign_out_btn.setEnabled(True)
        self.status_label.setText(f"Signed in: {bundle.method.value}")
        self.main.settings.last_auth_method = bundle.method.value
        self.main.settings.last_tenant_id = self.tenant_edit.text().strip()
        self.main.settings.last_client_id = self.client_edit.text().strip()
        self.main.settings.save()
        self.main.auth_changed.emit(bundle)
        self._fetch_subscriptions()

    def _on_sign_in_failed(self, error: str) -> None:
        self.sign_in_btn.setEnabled(True)
        self.status_label.setText(f"Sign-in failed: {error}")
        QMessageBox.critical(self, "Sign-in failed", error)

    def _on_sign_out(self) -> None:
        self.main.auth.sign_out()
        self.subs_list.clear()
        self.sign_out_btn.setEnabled(False)
        self.status_label.setText("Signed out")
        self.main.auth_changed.emit(None)

    def _fetch_subscriptions(self) -> None:
        self.subs_list.clear()
        self.subs_list.addItem("Loading subscriptions...")
        self._subs_worker = _SubsWorker(self.main.auth)
        self._subs_worker.finished_ok.connect(self._on_subs_ok)
        self._subs_worker.failed.connect(self._on_subs_failed)
        self._subs_worker.start()

    def _on_subs_ok(self, subs: list) -> None:
        from PyQt6.QtCore import Qt
        self.subs_list.blockSignals(True)
        try:
            self.subs_list.clear()
            saved = set(self.main.settings.last_subscription_ids or [])
            for s in subs:
                label = f"{s.get('name')}  -  {s.get('id')}  [{s.get('state')}]"
                item = QListWidgetItem(label)
                item.setData(0x0100 + 1, s.get("id"))  # custom user-data role
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                # First-run default: select all subscriptions. On subsequent
                # runs honour whatever the user previously persisted.
                if saved:
                    checked = s.get("id") in saved
                else:
                    checked = True
                item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
                self.subs_list.addItem(item)
            if not subs:
                placeholder = QListWidgetItem("(no subscriptions visible to this principal)")
                placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
                self.subs_list.addItem(placeholder)
        finally:
            self.subs_list.blockSignals(False)
        self._update_subs_count()

    def _on_subs_failed(self, error: str) -> None:
        from PyQt6.QtCore import Qt
        self.subs_list.clear()
        item = QListWidgetItem(f"Could not list subscriptions: {error}")
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.subs_list.addItem(item)
        self._update_subs_count()

    # ----------------------------------------------- OS target (macOS/Linux)
    def _on_target_toggled(self) -> None:
        self.ssh_form_box.setVisible(self.r_ssh.isChecked())

    def os_target(self):
        """Build a MachineTarget from current settings, or return None."""
        from ...targets import LocalTarget, SshTarget
        if self.r_local.isChecked():
            return LocalTarget()
        host = self.ssh_host_edit.text().strip()
        if not host:
            raise ValueError("SSH host is required.")
        return SshTarget(
            host=host,
            port=self.ssh_port_spin.value(),
            username=self.ssh_user_edit.text().strip() or None,
            password=self.ssh_password_edit.text() or None,
            key_path=self.ssh_key_edit.text().strip() or None,
            sudo=self.ssh_sudo_chk.isChecked(),
            sudo_password=self.ssh_sudo_password_edit.text() or None,
        )

    # Backwards-compatible alias for older callers.
    def macos_target(self):
        return self.os_target()

    def persist_target_settings(self) -> None:
        s = self.main.settings
        kind = "ssh" if self.r_ssh.isChecked() else "local"
        s.macos_target_kind = kind
        if hasattr(s, "os_target_kind"):
            s.os_target_kind = kind
        s.macos_ssh_host = self.ssh_host_edit.text().strip()
        s.macos_ssh_port = self.ssh_port_spin.value()
        s.macos_ssh_user = self.ssh_user_edit.text().strip()
        s.macos_ssh_key_path = self.ssh_key_edit.text().strip()
        s.macos_ssh_use_sudo = self.ssh_sudo_chk.isChecked()
        s.save()

    def _on_test_target(self) -> None:
        self.target_status.setText("Testing...")
        try:
            tgt = self.os_target()
        except Exception as exc:
            self.target_status.setText(f"FAILED: {exc}")
            return

        # Try POSIX `uname` first; if that fails, try Windows `cmd /c ver`.
        try:
            res = tgt.run(["uname", "-a"], timeout=10.0)
        except Exception:
            res = None
        if res is not None and res.rc == 0 and (
            "Darwin" in res.stdout or "Linux" in res.stdout
        ):
            kind = "macOS" if "Darwin" in res.stdout else "Linux"
            self.target_status.setText(f"OK ({kind}): {res.stdout.strip()[:200]}")
            self.persist_target_settings()
            tgt.close()
            return

        try:
            wres = tgt.run(["cmd", "/c", "ver"], timeout=10.0)
        except Exception as exc:
            self.target_status.setText(f"FAILED: {exc}")
            tgt.close()
            return
        finally:
            pass

        if wres.rc == 0 and "Windows" in wres.stdout:
            self.target_status.setText(f"OK (Windows): {wres.stdout.strip()[:200]}")
            self.persist_target_settings()
        elif res is not None and res.rc == 0:
            self.target_status.setText(
                f"Reachable but does not look like macOS / Linux / Windows: "
                f"{res.stdout.strip()[:200]}")
        else:
            err = (wres.stderr or wres.stdout or "").strip()[:200]
            self.target_status.setText(
                f"Command failed (rc={wres.rc}): {err}")
        tgt.close()

    def selected_subscription_ids(self) -> list[str]:
        from PyQt6.QtCore import Qt
        ids: list[str] = []
        for i in range(self.subs_list.count()):
            item = self.subs_list.item(i)
            if item is None:
                continue
            if not (item.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                continue
            if item.checkState() == Qt.CheckState.Checked:
                sub_id = item.data(0x0100 + 1)
                if sub_id:
                    ids.append(str(sub_id))
        return ids
