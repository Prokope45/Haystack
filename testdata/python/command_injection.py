from flask import request
import subprocess

def handler():
    target = request.args.get("target")
    cmd = "ping -c 1 " + target
    subprocess.run(cmd, shell=True)
