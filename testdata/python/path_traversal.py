from flask import request

def read_log():
    log_name = request.args["log"]
    full_path = "/var/log/" + log_name
    return open(full_path, "r").read()
