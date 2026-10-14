"""Gunicorn settings for running the portal on a Linux server / in Docker.

    gunicorn -c gunicorn.conf.py app:app

One worker process with several threads: login lockouts and firewall status are kept
in memory and data files are protected by in-process locks, so they must all live in
a single process. Threads let several users work at the same time.
"""
import os

bind = f"{os.environ.get('HOST', '0.0.0.0')}:{os.environ.get('PORT', '5555')}"
workers = 1
threads = int(os.environ.get("GUNICORN_THREADS", "8"))
worker_class = "gthread"
timeout = 120          # "Check all firewalls" and DHCP imports can take a while
graceful_timeout = 30
accesslog = "-"        # log requests to stdout (docker logs)
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
