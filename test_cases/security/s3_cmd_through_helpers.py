import os
from flask import Flask, request

app = Flask(__name__)


def read_host():
    return request.args.get("host")


def build_command(host):
    return "ping -c 1 " + host


@app.route("/ping")
def ping():
    command = build_command(read_host())
    exit_code = os.system(command)
    return {"reachable": exit_code == 0}
