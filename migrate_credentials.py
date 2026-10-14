"""Convert firewall passwords in firewalls.json from Windows DPAPI to the portable Fernet format.

Run this ONCE on the Windows PC (as the same Windows user) that created firewalls.json,
before moving the data to a Linux server / Docker container:

    1. Set the key you will also use on the server (or let one be created in .firewall.key):
         $env:FIREWALL_KEY = "<key>"
    2. python migrate_credentials.py
    3. Copy firewalls.json, users.json, audit.log (and .firewall.key if you did not set
       FIREWALL_KEY) to the server's data folder.

A backup of the original file is written next to it. Values that are already Fernet are left as they are.
"""
import json
import os
import shutil
import sys
from datetime import datetime

import credential_store
import firewalls


def main():
    path = firewalls.FIREWALLS_FILE
    if not os.path.exists(path):
        print(f"Nothing to do: {path} does not exist.")
        return
    with open(path, encoding="utf-8") as f:
        items = json.load(f)

    converted, failed = [], []
    for fw in items:
        if credential_store.is_fernet(fw.get("password", "")):
            continue
        try:
            fw["password"] = credential_store.encrypt(credential_store.decrypt(fw["password"]))
            converted.append(fw["name"])
        except OSError as e:
            failed.append(f"{fw['name']}: {e}")

    if not converted:
        print("No DPAPI passwords converted.")
    else:
        backup = f"{path}.dpapi-backup-{datetime.now():%Y%m%d-%H%M%S}"
        shutil.copy2(path, backup)
        firewalls._save(items)
        print(f"Converted {len(converted)} firewall(s): {', '.join(converted)}")
        print(f"Backup of the original: {backup}")
    if failed:
        print("Could not convert (re-enter these passwords in the portal):")
        print("\n".join(f"  - {x}" for x in failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
