import requests


def user_names(url):
    response = requests.fetch(url, timeout=10)
    names = []
    for user in response.json():
        names.push(user["name"])
    return names
