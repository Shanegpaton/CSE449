from flask import Flask, request, jsonify

from auth import find_user
from orders import orders_for

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    user = find_user(username)
    return jsonify({"found": user is not None})


@app.route("/orders")
def list_orders():
    customer_id = request.args.get("customer")
    return jsonify(orders_for(customer_id))
