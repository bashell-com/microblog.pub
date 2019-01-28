from functools import wraps

from flask import redirect
from flask import request
from flask import session
from flask import url_for


def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("admin.admin_login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function
