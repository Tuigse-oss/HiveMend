"""Drives Hivemend's window the way a keyboard or screen-reader user would,
through Windows UI Automation, and checks what it shows and does.

    python -I tests/ui/run_ui_tests.py path\\to\\Hivemend.exe [out-dir]

Run from an administrator prompt after `tests/ui/seed.ps1`, on a machine you
can test on. With HM_TEST_USER and HM_TEST_PASSWORD naming a standard
account whose own registry was seeded (`seed.ps1 -UserOnly`, run as that
account), it also repairs and restores that account's entry from a window
without administrator rights. Screenshots of each step, and of any failure,
go to out-dir (default: ui-test-output).
"""

import os
import shutil
import subprocess
import sys
import time
import winreg

from PIL import ImageGrab
from pywinauto import Application, Desktop, keyboard

EXE = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else "ui-test-output"
os.makedirs(OUT, exist_ok=True)

APP_PATHS = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
FINDINGS_LIST = 2000
BACKUPS_LIST = 2002

step_number = 0


def step(title):
    global step_number
    step_number += 1
    print(f"\n== {step_number}. {title}", flush=True)


def shot(name):
    ImageGrab.grab().save(os.path.join(OUT, f"{step_number:02d}-{name}.png"))


def wait_for(what, check, timeout=60.0, every=0.5):
    deadline = time.time() + timeout
    while True:
        result = check()
        if result:
            return result
        if time.time() > deadline:
            raise AssertionError(f"timed out after {timeout:.0f} s waiting for {what}")
        time.sleep(every)


def powershell(command, timeout=120.0):
    try:
        return subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            text=True,
            timeout=timeout,
        ).strip()
    except subprocess.TimeoutExpired:
        raise AssertionError(f"powershell hung for {timeout:.0f} s: {command[:80]}...")


def key_exists(hive, path):
    try:
        winreg.CloseKey(winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY))
        return True
    except FileNotFoundError:
        return False


class Hivemend:
    """A running Hivemend window, started as this account or another."""

    def __init__(self, exe, user=None):
        if user is None:
            self.pid = subprocess.Popen([exe]).pid
        else:
            # Starts on this desktop as the other account, with its profile
            # (and so its own part of the registry) loaded. The password is
            # folded into a SecureString with plain .NET calls because the
            # ConvertTo-SecureString cmdlet fails to load on some machines
            # (CouldNotAutoloadMatchingModule), which then hung the suite.
            self.pid = int(powershell(
                f"$s = New-Object Security.SecureString; "
                f"$env:HM_TEST_PASSWORD.ToCharArray() | ForEach-Object {{ $s.AppendChar($_) }}; "
                f"$c = New-Object Management.Automation.PSCredential('{user}', $s); "
                f"(Start-Process '{exe}' -Credential $c -LoadUserProfile "
                f"-WorkingDirectory '{os.path.dirname(exe)}' -PassThru).Id"
            ))
            # The new process must own a window on THIS desktop: on another
            # window station, UI Automation calls below can block forever,
            # past every Python-level timeout, with no output at all.
            def on_this_desktop():
                handle = powershell(
                    f"(Get-Process -Id {self.pid} -ErrorAction Stop).MainWindowHandle"
                )
                return handle != "0"
            try:
                wait_for("a window on this desktop", on_this_desktop, timeout=60)
            except AssertionError:
                raise AssertionError(
                    f"pid {self.pid} has no window on this desktop; "
                    "the standard-user checks need an interactive session"
                )
        self.uia = Application(backend="uia").connect(process=self.pid, timeout=30)
        self.win32 = Application(backend="win32").connect(process=self.pid, timeout=30)
        self.window = self.uia.window(title="Hivemend", control_type="Window")
        self.window.wait("visible", timeout=30)

    # -- what a screen reader sees --------------------------------------

    def buttons(self):
        return [b.window_text() for b in self.window.descendants(control_type="Button")]

    def texts(self):
        return [t.window_text() for t in self.window.descendants(control_type="Text")]

    def has_text(self, starting):
        return next((t for t in self.texts() if t.startswith(starting)), None)

    def press(self, name):
        """Press a button by its accessible name, as a screen reader would."""
        matches = [b for b in self.window.descendants(control_type="Button")
                   if b.window_text() == name and b.is_visible()]
        assert matches, f"no button named {name!r}; buttons: {self.buttons()}"
        matches[0].invoke()

    def go(self, shortcut, page):
        self.window.set_focus()
        keyboard.send_keys(shortcut)
        wait_for(f"the {page} page", lambda: f"{page}, current page" in self.buttons())

    # -- dialogs ----------------------------------------------------------

    def dialog(self, timeout=30.0):
        """The next message box Hivemend shows: its text, and the box."""
        def find():
            boxes = Desktop(backend="win32").windows(class_name="#32770", process=self.pid)
            return boxes[0] if boxes else None
        box = wait_for("a message box", find, timeout)
        text = " ".join(s.window_text() for s in box.children(class_name="Static")).strip()
        print(f"   dialog: {text!r}")
        return text, box

    def answer(self, box, choice):
        """Press `choice`; a box without it (a notice) is dismissed with OK."""
        names = {"yes": ["&Yes", "Yes"], "no": ["&No", "No"], "ok": ["OK"]}[choice]
        buttons = box.children(class_name="Button")
        for wanted in (names, ["OK"]):
            for button in buttons:
                if button.window_text() in wanted:
                    button.click()
                    return
        raise AssertionError(f"no {choice} button in the dialog")

    def answer_until(self, choice, until, timeout=120.0):
        """Answer message boxes with `choice` until one contains `until`,
        which is returned unanswered. Any other result fails the test."""
        deadline = time.time() + timeout
        while True:
            text, box = self.dialog(timeout=max(1.0, deadline - time.time()))
            shot("dialog")
            if until in text:
                return text, box
            if "could not" in text or "Nothing was changed" in text:
                raise AssertionError(f"expected {until!r}, got: {text}")
            self.answer(box, choice)

    # -- the findings list ------------------------------------------------

    def findings(self):
        lv = self.win32.window(title="Hivemend").child_window(control_id=FINDINGS_LIST).wrapper_object()
        rows = [(i, [lv.get_item(i, column).text() for column in range(4)])
                for i in range(lv.item_count())]
        return lv, rows

    def rows_for(self, marker):
        return [(i, cells) for i, cells in self.findings()[1]
                if any(marker in cell for cell in cells)]

    def row_for(self, marker):
        rows = self.rows_for(marker)
        assert len(rows) == 1, f"{marker} is listed {len(rows)} times: {rows}"
        return rows[0]

    def scan(self):
        self.press("Scan now")
        wait_for("scan results", lambda: self.has_text("Scan Results"), timeout=600, every=2)
        shot("results")

    def close(self):
        subprocess.run(["taskkill", "/PID", str(self.pid), "/F"], capture_output=True)


def checked(app, run):
    try:
        run(app)
    except BaseException:
        shot("failure")
        print("\nVisible buttons:", app.buttons())
        print("Visible texts:", app.texts())
        raise
    finally:
        app.close()


def as_administrator(app):
    step("Home is readable: sidebar, status, and Scan now have names")
    shot("home")
    buttons = app.buttons()
    for name in ["Home, current page", "Scan", "Restore", "Programs", "Settings", "Scan now"]:
        assert name in buttons, f"{name!r} not found; buttons: {buttons}"
    assert app.has_text("No scan yet"), f"no status line; texts: {app.texts()}"

    step("Ctrl+3 opens Restore, Ctrl+1 goes back Home")
    app.go("^3", "Restore")
    app.go("^1", "Home")

    step("Scan now runs a scan and lists each seeded entry once")
    app.scan()

    step("An administrator window says what it will and will not change")
    _, user = app.row_for("hivemend-ci-user")
    print("   per-user:", user)
    assert user[3] == "Fix from Hivemend without administrator rights", user
    _, default = app.row_for("hivemend-ci-default")
    print("   App Paths, default permissions:", default)
    assert default[3] == "Protected, left alone (information)", default
    _, locked = app.row_for("hivemend-ci-fixable")
    print("   locked key inside App Paths:", locked)
    # Removing it could not be undone: a restore would have to write into
    # App Paths, which standard accounts can change.
    assert locked[3] == "Protected, left alone (information)", locked


def as_standard_user(app, user_hive):
    entry = APP_PATHS + r"\hivemend-ci-user.exe"
    assert key_exists(winreg.HKEY_USERS, f"{user_hive}\\{entry}"), "the account's entry was not seeded"

    step("A normal window offers the account's own entry for repair")
    app.scan()
    row, user = app.row_for("hivemend-ci-user")
    print("   per-user:", user)
    assert user[3] == "Delete key", user

    step("Repair only that entry")
    app.press("Untick All")
    lv, _ = app.findings()
    lv.item(row).check()
    wait_for("the repair button to count one entry", lambda: "Repair Ticked (1)" in app.buttons())
    app.press("Repair Ticked (1)")
    text, box = app.dialog()
    assert text.startswith("Repair 1 entry?"), text
    app.answer(box, "yes")
    text, box = app.answer_until("ok", "Repair finished", timeout=300)
    assert "Removed: 1" in text, text
    app.answer(box, "ok")
    assert not key_exists(winreg.HKEY_USERS, f"{user_hive}\\{entry}"), "the repaired key is still there"
    assert not app.rows_for("hivemend-ci-user"), "the repaired entry is still listed"
    shot("repaired")

    step("Restore puts it back")
    app.go("^3", "Restore")
    backups = app.win32.window(title="Hivemend").child_window(control_id=BACKUPS_LIST).wrapper_object()
    wait_for("a backup in the list", lambda: backups.item_count() > 0)
    backups.item(0).select()
    app.press("Restore Selected Backup")
    text, box = app.answer_until("yes", "Restored", timeout=120)
    app.answer(box, "ok")
    assert key_exists(winreg.HKEY_USERS, f"{user_hive}\\{entry}"), "the restore did not put the key back"
    shot("restored")


def main():
    checked(Hivemend(EXE), as_administrator)

    user = os.environ.get("HM_TEST_USER")
    if not user or not os.environ.get("HM_TEST_PASSWORD"):
        print("\nHM_TEST_USER is not set: skipping the standard-account checks.")
    else:
        # The other account needs a copy it can read and run.
        folder = r"C:\HivemendTest"
        os.makedirs(folder, exist_ok=True)
        exe = shutil.copy(EXE, os.path.join(folder, "Hivemend.exe"))
        sid = powershell(
            f"(New-Object Security.Principal.NTAccount('{user}'))"
            ".Translate([Security.Principal.SecurityIdentifier]).Value"
        )
        checked(Hivemend(exe, user), lambda app: as_standard_user(app, sid))
    print("\nAll UI checks passed.")


if __name__ == "__main__":
    main()
