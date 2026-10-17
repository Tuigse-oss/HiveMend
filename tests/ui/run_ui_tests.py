"""Drives Hivemend's window the way a keyboard or screen-reader user would,
through Windows UI Automation, and checks what it shows and does.

    python -I tests/ui/run_ui_tests.py path\\to\\Hivemend.exe [out-dir]

Run from an administrator prompt after `tests/ui/seed.ps1`, on a machine you
can test on: it repairs and restores the seeded entries. Screenshots of each
step, and of any failure, go to out-dir (default: ui-test-output).
"""

import os
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
FIXABLE = (winreg.HKEY_LOCAL_MACHINE, APP_PATHS + r"\hivemend-ci-fixable.exe")
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


def key_exists(hive_and_path):
    hive, path = hive_and_path
    try:
        winreg.CloseKey(winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY))
        return True
    except FileNotFoundError:
        return False


class Hivemend:
    def __init__(self, exe):
        self.process = subprocess.Popen([exe])
        self.uia = Application(backend="uia").connect(process=self.process.pid, timeout=30)
        self.win32 = Application(backend="win32").connect(process=self.process.pid, timeout=30)
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

    # -- dialogs ----------------------------------------------------------

    def dialog(self, timeout=30.0):
        """The next message box Hivemend shows: its text, and the box."""
        def find():
            boxes = Desktop(backend="win32").windows(class_name="#32770", process=self.process.pid)
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

    def answer_all(self, choice, until, timeout=120.0):
        """Answer message boxes with `choice` until one contains `until`."""
        deadline = time.time() + timeout
        while True:
            text, box = self.dialog(timeout=max(1.0, deadline - time.time()))
            shot("dialog")
            if until in text:
                return text, box
            self.answer(box, choice)

    # -- the findings list ------------------------------------------------

    def findings(self):
        lv = self.win32.window(title="Hivemend").child_window(control_id=FINDINGS_LIST).wrapper_object()
        rows = []
        for index in range(lv.item_count()):
            cells = [lv.get_item(index, column).text() for column in range(4)]
            rows.append((index, cells))
        return lv, rows

    def row_for(self, marker):
        lv, rows = self.findings()
        for index, cells in rows:
            if any(marker in cell for cell in cells):
                return lv, index, cells
        raise AssertionError(f"no row mentions {marker!r} among {len(rows)} rows")

    def close(self):
        if self.process.poll() is None:
            self.process.kill()


def main():
    app = Hivemend(EXE)
    try:
        run(app)
    except BaseException:
        shot("failure")
        print("\nVisible buttons:", app.buttons())
        print("Visible texts:", app.texts())
        raise
    finally:
        app.close()
    print("\nAll UI checks passed.")


def run(app):
    step("Home is readable: sidebar, status, and Scan now have names")
    shot("home")
    buttons = app.buttons()
    for name in ["Home, current page", "Scan", "Restore", "Programs", "Settings", "Scan now"]:
        assert name in buttons, f"{name!r} not found; buttons: {buttons}"
    assert app.has_text("No scan yet"), f"no status line; texts: {app.texts()}"

    step("Ctrl+3 opens Restore, Ctrl+1 goes back Home")
    app.window.set_focus()
    keyboard.send_keys("^3")
    wait_for("the Restore page", lambda: app.has_text("Restore"))
    assert "Restore, current page" in app.buttons()
    keyboard.send_keys("^1")
    wait_for("Home", lambda: "Home, current page" in app.buttons())

    step("Scan now runs a scan and shows results")
    app.press("Scan now")
    wait_for("scan results", lambda: app.has_text("Scan Results"), timeout=600, every=2)
    shot("results")

    step("Each seeded entry is shown for what this window can do with it")
    _, _, user = app.row_for("hivemend-ci-user")
    print("   per-user:", user)
    assert user[3] == "Fix from Hivemend without administrator rights", user
    _, _, default = app.row_for("hivemend-ci-default")
    print("   default permissions:", default)
    # Windows lets standard accounts' sessions change App Paths by default,
    # so an administrator window leaves it alone.
    assert default[3] == "Protected, left alone (information)", default
    for marker in ["hivemend-ci-user", "hivemend-ci-default", "hivemend-ci-fixable"]:
        rows = [cells for _, cells in app.findings()[1] if any(marker in c for c in cells)]
        assert len(rows) == 1, f"{marker} is listed {len(rows)} times: {rows}"
    _, fixable_row, fixable = app.row_for("hivemend-ci-fixable")
    print("   admin-only:", fixable)
    assert fixable[3].startswith("Delete key"), fixable

    step("Only the admin-only entry is ticked, then repaired")
    app.press("Untick All")
    lv, _, _ = app.row_for("hivemend-ci-fixable")
    lv.item(fixable_row).check()
    wait_for("the repair button to count one entry", lambda: "Repair Ticked (1)" in app.buttons())
    app.press("Repair Ticked (1)")
    text, box = app.dialog()
    assert text.startswith("Repair 1 entry?"), text
    app.answer(box, "yes")
    text, box = app.answer_all("ok", until="Repair finished", timeout=300)
    assert "Removed: 1" in text, text
    app.answer(box, "ok")
    assert not key_exists(FIXABLE), "the repaired key is still there"
    for marker in ["hivemend-ci-fixable"]:
        rows = [cells for _, cells in app.findings()[1] if any(marker in c for c in cells)]
        assert not rows, f"repaired entry still listed: {rows}"
    shot("repaired")

    step("Restore puts the repaired entry back")
    keyboard.send_keys("^3")
    wait_for("the Restore page", lambda: "Restore, current page" in app.buttons())
    backups = app.win32.window(title="Hivemend").child_window(control_id=BACKUPS_LIST).wrapper_object()
    wait_for("a backup in the list", lambda: backups.item_count() > 0)
    backups.item(0).select()
    app.press("Restore Selected Backup")
    text, box = app.answer_all("yes", until="Restored", timeout=120)
    app.answer(box, "ok")
    assert key_exists(FIXABLE), "the restore did not put the key back"
    shot("restored")


if __name__ == "__main__":
    main()
