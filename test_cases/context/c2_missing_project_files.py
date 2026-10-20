from .models import User
from utils import send_email
import config


def send_welcome(user_id):
    user = User.get(user_id)
    subject = "Welcome to " + config.SITE_NAME
    send_email(user.email, subject, "Thanks for signing up.")
    return True
