"""Manage GUI login users from the command line.

Usage:
    python manage_users.py add <username> [admin|user]   (prompts for password; default role: admin;
                                                          also resets an existing user's password)
    python manage_users.py remove <username>
    python manage_users.py list

Once an admin exists, users can also be managed from the "User Management" tab in the GUI.
"""
import getpass
import sys

import auth


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("add", "remove", "list"):
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    if command == "list":
        users = auth.list_users()
        print("\n".join(f"{u['username']:<24} {u['role']}" for u in users) if users else "No users yet.")
        return

    if len(sys.argv) not in (3, 4):
        print(__doc__)
        sys.exit(1)
    username = sys.argv[2].strip()

    try:
        if command == "remove":
            auth.delete_user(username)
            print(f"Removed '{username}'.")
            return

        role = sys.argv[3] if len(sys.argv) == 4 else "admin"
        password = getpass.getpass(f"Password for '{username}': ")
        if password != getpass.getpass("Confirm password: "):
            print("Passwords do not match.")
            sys.exit(1)
        auth.set_user(username, password, role)
        print(f"User '{username}' saved with role '{role}'.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
