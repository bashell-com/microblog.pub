import json
from urllib.parse import urlparse

from flask import abort
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
import flask
from flask_wtf.csrf import CSRFProtect
from little_boxes import activitypub as ap
from little_boxes.activitypub import ActivityType
from little_boxes.activitypub import get_backend
from passlib.hash import bcrypt
from u2flib_server import u2f

from activitypub import Box
from config import BASE_URL
from config import DB
from config import DOMAIN
from config import ID
from config import PASS
from config import USERNAME
from utils.headers import noindex
from utils.login import login_required
from utils.lookup import lookup
from utils.query import paginated_query
from utils.thread import _build_thread

blueprint = flask.Blueprint('admin', __name__, template_folder='templates')
csrf = CSRFProtect(current_app)


def verify_pass(pwd):
    return bcrypt.verify(pwd, PASS)


@blueprint.route("/admin", methods=["GET"])
@login_required
def admin():
    q = {
        "meta.deleted": False,
        "meta.undo": False,
        "type": ActivityType.LIKE.value,
        "box": Box.OUTBOX.value,
    }
    col_liked = DB.activities.count(q)

    return render_template(
        "admin.html",
        instances=list(DB.instances.find()),
        inbox_size=DB.activities.count({"box": Box.INBOX.value}),
        outbox_size=DB.activities.count({"box": Box.OUTBOX.value}),
        col_liked=col_liked,
        col_followers=DB.activities.count(
            {
                "box": Box.INBOX.value,
                "type": ActivityType.FOLLOW.value,
                "meta.undo": False,
            }
        ),
        col_following=DB.activities.count(
            {
                "box": Box.OUTBOX.value,
                "type": ActivityType.FOLLOW.value,
                "meta.undo": False,
            }
        ),
    )


@blueprint.route("/admin/lookup", methods=["GET", "POST"])
@login_required
def admin_lookup():
    data = None
    meta = None
    if request.method == "POST":
        if request.form.get("url"):
            data = lookup(request.form.get("url"))
            if data.has_type(ActivityType.ANNOUNCE):
                meta = dict(
                    object=data.get_object().to_dict(),
                    object_actor=data.get_object().get_actor().to_dict(),
                    actor=data.get_actor().to_dict(),
                )

        current_app.logger.debug(data)
    return render_template(
        "lookup.html", data=data, meta=meta, url=request.form.get("url")
    )


@blueprint.route("/admin/thread")
@login_required
def admin_thread():
    data = DB.activities.find_one(
        {
            "$or": [
                {"remote_id": request.args.get("oid")},
                {"activity.object.id": request.args.get("oid")},
            ]
        }
    )
    if not data:
        abort(404)
    if data["meta"].get("deleted", False):
        abort(410)
    thread = _build_thread(data)

    tpl = "note.html"
    if request.args.get("debug"):
        tpl = "note_debug.html"
    return render_template(tpl, thread=thread, note=data)


@blueprint.route("/admin/new", methods=["GET"])
@login_required
def admin_new():
    reply_id = None
    content = ""
    thread = []
    current_app.logger.debug(request.args)
    if request.args.get("reply"):
        data = DB.activities.find_one({"activity.object.id": request.args.get("reply")})
        if data:
            reply = ap.parse_activity(data["activity"])
        else:
            data = dict(
                meta={},
                activity=dict(
                    object=get_backend().fetch_iri(request.args.get("reply"))
                ),
            )
            reply = ap.parse_activity(data["activity"]["object"])

        reply_id = reply.id
        if reply.ACTIVITY_TYPE == ActivityType.CREATE:
            reply_id = reply.get_object().id
        actor = reply.get_actor()
        domain = urlparse(actor.id).netloc
        # FIXME(tsileo): if reply of reply, fetch all participants
        content = f"@{actor.preferredUsername}@{domain} "
        thread = _build_thread(data)

    return render_template("new.html", reply=reply_id, content=content, thread=thread)


@blueprint.route("/admin/notifications")
@login_required
def admin_notifications():
    # FIXME(tsileo): show unfollow (performed by the current actor) and liked???
    mentions_query = {
        "type": ActivityType.CREATE.value,
        "activity.object.tag.type": "Mention",
        "activity.object.tag.name": f"@{USERNAME}@{DOMAIN}",
        "meta.deleted": False,
    }
    replies_query = {
        "type": ActivityType.CREATE.value,
        "activity.object.inReplyTo": {"$regex": f"^{BASE_URL}"},
    }
    announced_query = {
        "type": ActivityType.ANNOUNCE.value,
        "activity.object": {"$regex": f"^{BASE_URL}"},
    }
    new_followers_query = {"type": ActivityType.FOLLOW.value}
    unfollow_query = {
        "type": ActivityType.UNDO.value,
        "activity.object.type": ActivityType.FOLLOW.value,
    }
    likes_query = {
        "type": ActivityType.LIKE.value,
        "activity.object": {"$regex": f"^{BASE_URL}"},
    }
    followed_query = {"type": ActivityType.ACCEPT.value}
    q = {
        "box": Box.INBOX.value,
        "$or": [
            mentions_query,
            announced_query,
            replies_query,
            new_followers_query,
            followed_query,
            unfollow_query,
            likes_query,
        ],
    }
    inbox_data, older_than, newer_than = paginated_query(DB.activities, q)

    return render_template(
        "stream.html",
        inbox_data=inbox_data,
        older_than=older_than,
        newer_than=newer_than,
    )


@blueprint.route("/admin/stream")
@login_required
def admin_stream():
    q = {"meta.stream": True, "meta.deleted": False}

    tpl = "stream.html"
    if request.args.get("debug"):
        tpl = "stream_debug.html"
        if request.args.get("debug_inbox"):
            q = {}

    inbox_data, older_than, newer_than = paginated_query(
        DB.activities, q, limit=int(request.args.get("limit", 25))
    )

    return render_template(
        tpl, inbox_data=inbox_data, older_than=older_than, newer_than=newer_than
    )


@blueprint.route("/admin/logout")
@login_required
def admin_logout():
    session["logged_in"] = False
    return redirect("/")


@blueprint.route("/login", methods=["POST", "GET"])
@noindex
def admin_login():
    if session.get("logged_in") is True:
        return redirect(url_for(".admin_notifications"))

    devices = [doc["device"] for doc in DB.u2f.find()]
    u2f_enabled = True if devices else False
    if request.method == "POST":
        csrf.protect()
        pwd = request.form.get("pass")
        if pwd and verify_pass(pwd):
            if devices:
                resp = json.loads(request.form.get("resp"))
                current_app.logger.debug(resp)
                try:
                    u2f.complete_authentication(session["challenge"], resp)
                except ValueError as exc:
                    current_app.logger.debug("failed", exc)
                    abort(401)
                    return
                finally:
                    session["challenge"] = None

            session["logged_in"] = True
            return redirect(
                request.args.get("redirect") or url_for(".admin_notifications")
            )
        else:
            abort(401)

    payload = None
    if devices:
        payload = u2f.begin_authentication(ID, devices)
        session["challenge"] = payload

    return render_template("login.html", u2f_enabled=u2f_enabled, payload=payload)
