# DEMO FINDING (SAST / easy-medium, Python): classic Flask anti-patterns.
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/report")
def report():
    # CWE-89: SQL injection via string formatting
    conn = sqlite3.connect("reports.db")
    name = request.args.get("name")
    rows = conn.execute("SELECT * FROM reports WHERE name = '%s'" % name).fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping():
    # CWE-78: command injection with shell=True
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/import", methods=["POST"])
def import_config():
    # CWE-502: unsafe YAML and pickle deserialization
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    state = pickle.loads(bytes.fromhex(request.args.get("state", "")))
    return {"cfg": str(cfg), "state": str(state)}


@app.route("/preview")
def preview():
    # CWE-1336: server-side template injection
    return render_template_string("<p>" + request.args.get("tpl", "") + "</p>")


@app.route("/webhook")
def webhook():
    # CWE-918 SSRF + CWE-295 TLS verification disabled
    return requests.get(request.args["url"], verify=False).text


@app.route("/logs")
def logs():
    # CWE-22: path traversal
    base_directory = "/var/log/app"
    file_path = os.path.abspath(os.path.join(base_directory, request.args["file"]))
    if file_path.startswith(base_directory):
        return open(file_path).read()
    else:
        return "Invalid file path", 400


if __name__ == "__main__":
    # CWE-489: debug mode exposes the Werkzeug console; binds to all interfaces
    app.run(host="0.0.0.0", debug=True)
