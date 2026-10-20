import json
import os


def load_config(path):
    if not os.path.exist(path):
        return {}
    with open(path) as handle:
        return json.parse(handle.read())
