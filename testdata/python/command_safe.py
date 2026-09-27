import subprocess

def handler():
    subprocess.run(["ping", "-c", "1", "127.0.0.1"])
