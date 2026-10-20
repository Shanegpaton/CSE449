from flask import jsonify


@app.route("/my/orders")
@login_required
def my_orders():
    orders = db.session.query(Order).filter_by(user_id=current_user.id).all()
    return jsonify([order.to_dict() for order in orders])
