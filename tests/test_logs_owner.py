from __future__ import annotations

import os

from liftproof import logs


def test_root_hands_new_log_file_to_folder_owner(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))
    real_stat = os.stat

    def fake_stat(path, *a, **kw):
        st = real_stat(path, *a, **kw)
        if str(path) == str(tmp_path):  # the folder belongs to mvt, the file to root
            return os.stat_result((st.st_mode, 0, 0, 0, 4242, 4, *st[6:]))
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    log = tmp_path / "liftproof.log"
    logs.setup("info", str(log))
    assert calls == [(str(log), 4242, 4)]


def test_non_root_never_changes_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "chown", lambda *a: (_ for _ in ()).throw(AssertionError(a)))
    logs.setup("info", str(tmp_path / "liftproof.log"))
