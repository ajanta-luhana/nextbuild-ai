"""Local administration: reset a password and clear a lockout.

    python -m autoforge.admin reset-password            (asks for user name and new password)
    python -m autoforge.admin unlock "user name"
Runs against the configured database (same environment variables as the server). Needs access to the machine, nothing else.
"""
from __future__ import annotations

import getpass
import sys

from autoforge.core.config import load_settings
from autoforge.core.db import Database, utcnow
from autoforge.security.passwords import hash_password, policy_problems


def _db() -> Database:
    return Database(load_settings().database_path)


def _find(db: Database, name: str):
    row = db.one("SELECT * FROM users WHERE lower(display_name)=lower(?)", (name.strip(),))
    if row is None:
        names = ", ".join(r["display_name"] for r in db.all("SELECT display_name FROM users ORDER BY created_at")) or "(none yet)"
        raise SystemExit(f"No such user. Existing users: {names}")
    return row


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in {"reset-password", "unlock", "list"}:
        print(__doc__)
        return 2
    db = _db()
    if argv[0] == "list":
        for r in db.all("SELECT display_name, role, locked_until FROM users ORDER BY created_at"):
            print(f"{r['display_name']}  role={r['role']}  locked_until={r['locked_until'] or '-'}")
        return 0
    name = argv[1] if len(argv) > 1 else input("User name: ")
    row = _find(db, name)
    if argv[0] == "unlock":
        db.run("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (row["id"],))
        print(f"Unlocked {row['display_name']}.")
        return 0
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    problems = policy_problems(pw, row["display_name"])
    if problems:
        raise SystemExit("Password rejected: " + " ".join(problems))
    now = utcnow()
    db.run("UPDATE users SET password_hash=?, password_changed_at=?, failed_logins=0, locked_until=NULL, updated_at=? WHERE id=?", (hash_password(pw), now, now, row["id"]))
    db.run("DELETE FROM sessions WHERE user_id=?", (row["id"],))
    print(f"Password reset for {row['display_name']}. All their sessions were signed out.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
