from datetime import datetime
from datetime import timezone
import json
import logging
import mimetypes
import os
import traceback
from typing import Any
from typing import Dict

from bson.objectid import ObjectId
from flask import Flask
from flask import Response
from flask import abort
from flask import jsonify as flask_jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
from flask import session
from flask import url_for
from flask_wtf.csrf import CSRFProtect
from itsdangerous import BadSignature
from little_boxes import activitypub as ap
from little_boxes.activitypub import ActivityType
from little_boxes.activitypub import _to_list
from little_boxes.activitypub import clean_activity
from little_boxes.activitypub import get_backend
from little_boxes.errors import ActivityGoneError
from little_boxes.errors import Error
from little_boxes.httpsig import HTTPSigAuth
from little_boxes.httpsig import verify_request
from little_boxes.webfinger import get_actor_url
from little_boxes.webfinger import get_remote_follow_template
from u2flib_server import u2f

from activitypub import Box
from activitypub import embed_collection
import activitypub
import admin
import api
from config import BASE_URL
from config import DB
from config import DOMAIN
from config import HEADERS
from config import ICON_URL
from config import ID
from config import KEY
from config import ME
from config import MEDIA_CACHE
from config import USERNAME
from config import VERSION
import config
import feeds
import filters
import indieauth
import migrations
import tasks
from utils.headers import noindex
from utils.key import get_secret_key
from utils.login import login_required
from utils.query import paginated_query
from utils.thread import _build_thread

back = activitypub.MicroblogPubBackend()
ap.use_backend(back)

MY_PERSON = ap.Person(**ME)

app = Flask(__name__)
app.register_blueprint(admin.blueprint)
app.register_blueprint(api.blueprint)
app.register_blueprint(feeds.blueprint)
app.register_blueprint(filters.blueprint)
app.register_blueprint(indieauth.blueprint)
app.register_blueprint(migrations.blueprint)
app.secret_key = get_secret_key("flask")
app.config.update(WTF_CSRF_CHECK_DEFAULT=False)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.jinja_env.strip_trailing_newlines = False
csrf = CSRFProtect(app)

logger = logging.getLogger(__name__)

# Hook up Flask logging with gunicorn
root_logger = logging.getLogger()
if os.getenv("FLASK_DEBUG"):
    logger.setLevel(logging.DEBUG)
    root_logger.setLevel(logging.DEBUG)
else:
    gunicorn_logger = logging.getLogger("gunicorn.error")
    root_logger.handlers = gunicorn_logger.handlers
    root_logger.setLevel(gunicorn_logger.level)

SIG_AUTH = HTTPSigAuth(KEY)


@app.context_processor
def inject_config():
    q = {
        "type": "Create",
        "activity.object.type": "Note",
        "activity.object.inReplyTo": None,
        "meta.deleted": False,
    }
    notes_count = DB.activities.find(
        {"box": Box.OUTBOX.value, "$or": [q, {"type": "Announce", "meta.undo": False}]}
    ).count()
    q = {"type": "Create", "activity.object.type": "Note", "meta.deleted": False}
    with_replies_count = DB.activities.find(
        {"box": Box.OUTBOX.value, "$or": [q, {"type": "Announce", "meta.undo": False}]}
    ).count()
    liked_count = DB.activities.count(
        {
            "box": Box.OUTBOX.value,
            "meta.deleted": False,
            "meta.undo": False,
            "type": ActivityType.LIKE.value,
        }
    )
    followers_q = {
        "box": Box.INBOX.value,
        "type": ActivityType.FOLLOW.value,
        "meta.undo": False,
    }
    following_q = {
        "box": Box.OUTBOX.value,
        "type": ActivityType.FOLLOW.value,
        "meta.undo": False,
    }

    return dict(
        microblogpub_version=VERSION,
        config=config,
        logged_in=session.get("logged_in", False),
        followers_count=DB.activities.count(followers_q),
        following_count=DB.activities.count(following_q),
        notes_count=notes_count,
        liked_count=liked_count,
        with_replies_count=with_replies_count,
        me=ME,
    )


@app.after_request
def set_x_powered_by(response):
    response.headers["X-Powered-By"] = "microblog.pub"
    return response


def jsonify(**data):
    if "@context" not in data:
        data["@context"] = config.DEFAULT_CTX
    return Response(
        response=json.dumps(data),
        headers={
            "Content-Type": "application/json"
            if app.debug
            else "application/activity+json"
        },
    )


def is_api_request():
    h = request.headers.get("Accept")
    if h is None:
        return False
    h = h.split(",")[0]
    if h in HEADERS or h == "application/json":
        return True
    return False


@app.errorhandler(ValueError)
def handle_value_error(error):
    logger.error(
        f"caught value error: {error!r}, {traceback.format_tb(error.__traceback__)}"
    )
    response = flask_jsonify(message=error.args[0])
    response.status_code = 400
    return response


@app.errorhandler(Error)
def handle_activitypub_error(error):
    logger.error(
        f"caught activitypub error {error!r}, {traceback.format_tb(error.__traceback__)}"
    )
    response = flask_jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

# @app.errorhandler(Exception)
# def handle_other_error(error):
#    logger.error(
#        f"caught error {error!r}, {traceback.format_tb(error.__traceback__)}"
#    )
#    response = flask_jsonify({})
#    response.status_code = 500
#    return response

# App migrations


ROBOTS_TXT = """User-agent: *
Disallow: /login
Disallow: /admin/
Disallow: /static/
Disallow: /media/
Disallow: /uploads/"""


@app.route("/robots.txt")
def robots_txt():
    return Response(response=ROBOTS_TXT, headers={"Content-Type": "text/plain"})


@app.route("/media/<media_id>")
@noindex
def serve_media(media_id):
    f = MEDIA_CACHE.fs.get(ObjectId(media_id))
    resp = app.response_class(f, direct_passthrough=True, mimetype=f.content_type)
    resp.headers.set("Content-Length", f.length)
    resp.headers.set("ETag", f.md5)
    resp.headers.set(
        "Last-Modified", f.uploadDate.strftime("%a, %d %b %Y %H:%M:%S GMT")
    )
    resp.headers.set("Cache-Control", "public,max-age=31536000,immutable")
    resp.headers.set("Content-Encoding", "gzip")
    return resp


@app.route("/uploads/<oid>/<fname>")
def serve_uploads(oid, fname):
    f = MEDIA_CACHE.fs.get(ObjectId(oid))
    resp = app.response_class(f, direct_passthrough=True, mimetype=f.content_type)
    resp.headers.set("Content-Length", f.length)
    resp.headers.set("ETag", f.md5)
    resp.headers.set(
        "Last-Modified", f.uploadDate.strftime("%a, %d %b %Y %H:%M:%S GMT")
    )
    resp.headers.set("Cache-Control", "public,max-age=31536000,immutable")
    resp.headers.set("Content-Encoding", "gzip")
    return resp


@app.route("/remote_follow", methods=["GET", "POST"])
def remote_follow():
    if request.method == "GET":
        return render_template("remote_follow.html")

    csrf.protect()
    profile = request.form.get("profile")
    if not profile.startswith("@"):
        profile = f"@{profile}"
    return redirect(
        get_remote_follow_template(profile).format(uri=f"{USERNAME}@{DOMAIN}")
    )


@app.route("/authorize_follow", methods=["GET", "POST"])
@login_required
def authorize_follow():
    if request.method == "GET":
        return render_template(
            "authorize_remote_follow.html", profile=request.args.get("profile")
        )

    actor = get_actor_url(request.form.get("profile"))
    if not actor:
        abort(500)

    q = {
        "box": Box.OUTBOX.value,
        "type": ActivityType.FOLLOW.value,
        "meta.undo": False,
        "activity.object": actor,
    }
    if DB.activities.count(q) > 0:
        return redirect("/following")

    follow = ap.Follow(actor=MY_PERSON.id, object=actor)
    tasks.post_to_outbox(follow)

    return redirect("/following")


@app.route("/u2f/register", methods=["GET", "POST"])
@login_required
def u2f_register():
    # TODO(tsileo): ensure no duplicates
    if request.method == "GET":
        payload = u2f.begin_registration(ID)
        session["challenge"] = payload
        return render_template("u2f.html", payload=payload)
    else:
        resp = json.loads(request.form.get("resp"))
        device, device_cert = u2f.complete_registration(session["challenge"], resp)
        session["challenge"] = None
        DB.u2f.insert_one({"device": device, "cert": device_cert})
        return ""


#######
# Activity pub migrations
@app.route("/drop_cache")
@login_required
def drop_cache():
    DB.actors.drop()
    return "Done"


CACHING = True


def _get_cached(type_="html", arg=None):
    if not CACHING:
        return None
    logged_in = session.get("logged_in")
    if not logged_in:
        cached = DB.cache2.find_one({"path": request.path, "type": type_, "arg": arg})
        if cached:
            app.logger.info("from cache")
            return cached['response_data']
    return None


def _cache(resp, type_="html", arg=None):
    if not CACHING:
        return None
    logged_in = session.get("logged_in")
    if not logged_in:
        DB.cache2.update_one(
            {"path": request.path, "type": type_, "arg": arg},
            {"$set": {"response_data": resp, "date": datetime.now(timezone.utc)}},
            upsert=True,
        )
    return None


@app.route("/")
def index():
    if is_api_request():
        return jsonify(**ME)
    cache_arg = f"{request.args.get('older_than', '')}:{request.args.get('newer_than', '')}"
    cached = _get_cached("html", cache_arg)
    if cached:
        return cached

    q = {
        "box": Box.OUTBOX.value,
        "type": {"$in": [ActivityType.CREATE.value, ActivityType.ANNOUNCE.value]},
        "activity.object.inReplyTo": None,
        "meta.deleted": False,
        "meta.undo": False,
        "$or": [{"meta.pinned": False}, {"meta.pinned": {"$exists": False}}],
    }

    pinned = []
    # Only fetch the pinned notes if we're on the first page
    if not request.args.get("older_than") and not request.args.get("newer_than"):
        q_pinned = {
            "box": Box.OUTBOX.value,
            "type": ActivityType.CREATE.value,
            "meta.deleted": False,
            "meta.undo": False,
            "meta.pinned": True,
        }
        pinned = list(DB.activities.find(q_pinned))

    outbox_data, older_than, newer_than = paginated_query(
        DB.activities, q, limit=25 - len(pinned)
    )

    resp = render_template(
        "index.html",
        outbox_data=outbox_data,
        older_than=older_than,
        newer_than=newer_than,
        pinned=pinned,
    )
    _cache(resp, "html", cache_arg)
    return resp


@app.route("/with_replies")
@login_required
def with_replies():
    q = {
        "box": Box.OUTBOX.value,
        "type": {"$in": [ActivityType.CREATE.value, ActivityType.ANNOUNCE.value]},
        "meta.deleted": False,
        "meta.undo": False,
    }
    outbox_data, older_than, newer_than = paginated_query(DB.activities, q)

    return render_template(
        "index.html",
        outbox_data=outbox_data,
        older_than=older_than,
        newer_than=newer_than,
    )


@app.route("/note/<note_id>")
def note_by_id(note_id):
    if is_api_request():
        return redirect(url_for("outbox_activity", item_id=note_id))

    data = DB.activities.find_one(
        {"box": Box.OUTBOX.value, "remote_id": back.activity_url(note_id)}
    )
    if not data:
        abort(404)
    if data["meta"].get("deleted", False):
        abort(410)
    thread = _build_thread(data)
    app.logger.info(f"thread={thread!r}")

    raw_likes = list(
        DB.activities.find(
            {
                "meta.undo": False,
                "meta.deleted": False,
                "type": ActivityType.LIKE.value,
                "$or": [
                    # FIXME(tsileo): remove all the useless $or
                    {"activity.object.id": data["activity"]["object"]["id"]},
                    {"activity.object": data["activity"]["object"]["id"]},
                ],
            }
        )
    )
    likes = []
    for doc in raw_likes:
        try:
            likes.append(doc["meta"]["actor"])
        except Exception:
            app.logger.exception(f"invalid doc: {doc!r}")
    app.logger.info(f"likes={likes!r}")

    raw_shares = list(
        DB.activities.find(
            {
                "meta.undo": False,
                "meta.deleted": False,
                "type": ActivityType.ANNOUNCE.value,
                "$or": [
                    {"activity.object.id": data["activity"]["object"]["id"]},
                    {"activity.object": data["activity"]["object"]["id"]},
                ],
            }
        )
    )
    shares = []
    for doc in raw_shares:
        try:
            shares.append(doc["meta"]["actor"])
        except Exception:
            app.logger.exception(f"invalid doc: {doc!r}")
    app.logger.info(f"shares={shares!r}")

    return render_template(
        "note.html", likes=likes, shares=shares, thread=thread, note=data
    )


@app.route("/nodeinfo")
def nodeinfo():
    response = _get_cached("api")
    cached = True
    if not response:
        cached = False
        q = {
            "box": Box.OUTBOX.value,
            "meta.deleted": False,  # TODO(tsileo): retrieve deleted and expose tombstone
            "type": {"$in": [ActivityType.CREATE.value, ActivityType.ANNOUNCE.value]},
        }

        response = json.dumps(
                {
                    "version": "2.0",
                    "software": {
                        "name": "microblogpub",
                        "version": f"Microblog.pub {VERSION}",
                    },
                    "protocols": ["activitypub"],
                    "services": {"inbound": [], "outbound": []},
                    "openRegistrations": False,
                    "usage": {"users": {"total": 1}, "localPosts": DB.activities.count(q)},
                    "metadata": {
                        "sourceCode": "https://github.com/tsileo/microblog.pub",
                        "nodeName": f"@{USERNAME}@{DOMAIN}",
                    },
                }
            )

    if not cached:
        _cache(response, "api")
    return Response(
        headers={
            "Content-Type": "application/json; profile=http://nodeinfo.diaspora.software/ns/schema/2.0#"
        },
        response=response,
    )


@app.route("/.well-known/nodeinfo")
def wellknown_nodeinfo():
    return flask_jsonify(
        links=[
            {
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.0",
                "href": f"{ID}/nodeinfo",
            }
        ]
    )


@app.route("/.well-known/webfinger")
def wellknown_webfinger():
    """Enable WebFinger support, required for Mastodon interopability."""
    # TODO(tsileo): move this to little-boxes?
    resource = request.args.get("resource")
    if resource not in [f"acct:{USERNAME}@{DOMAIN}", ID]:
        abort(404)

    out = {
        "subject": f"acct:{USERNAME}@{DOMAIN}",
        "aliases": [ID],
        "links": [
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": BASE_URL,
            },
            {"rel": "self", "type": "application/activity+json", "href": ID},
            {
                "rel": "http://ostatus.org/schema/1.0/subscribe",
                "template": BASE_URL + "/authorize_follow?profile={uri}",
            },
            {"rel": "magic-public-key", "href": KEY.to_magic_key()},
            {
                "href": ICON_URL,
                "rel": "http://webfinger.net/rel/avatar",
                "type": mimetypes.guess_type(ICON_URL)[0],
            },
        ],
    }

    return Response(
        response=json.dumps(out),
        headers={
            "Content-Type": "application/jrd+json; charset=utf-8"
            if not app.debug
            else "application/json"
        },
    )


def add_extra_collection(raw_doc: Dict[str, Any]) -> Dict[str, Any]:
    if raw_doc["activity"]["type"] != ActivityType.CREATE.value:
        return raw_doc

    raw_doc["activity"]["object"]["replies"] = embed_collection(
        raw_doc.get("meta", {}).get("count_direct_reply", 0),
        f'{raw_doc["remote_id"]}/replies',
    )

    raw_doc["activity"]["object"]["likes"] = embed_collection(
        raw_doc.get("meta", {}).get("count_like", 0), f'{raw_doc["remote_id"]}/likes'
    )

    raw_doc["activity"]["object"]["shares"] = embed_collection(
        raw_doc.get("meta", {}).get("count_boost", 0), f'{raw_doc["remote_id"]}/shares'
    )

    return raw_doc


def remove_context(activity: Dict[str, Any]) -> Dict[str, Any]:
    if "@context" in activity:
        del activity["@context"]
    return activity


def activity_from_doc(raw_doc: Dict[str, Any], embed: bool=False) -> Dict[str, Any]:
    raw_doc = add_extra_collection(raw_doc)
    activity = clean_activity(raw_doc["activity"])
    if embed:
        return remove_context(activity)
    return activity


@app.route("/outbox", methods=["GET", "POST"])
def outbox():
    if request.method == "GET":
        if not is_api_request():
            abort(404)
        # TODO(tsileo): returns the whole outbox if authenticated
        q = {
            "box": Box.OUTBOX.value,
            "meta.deleted": False,
            "type": {"$in": [ActivityType.CREATE.value, ActivityType.ANNOUNCE.value]},
        }
        return jsonify(
            **activitypub.build_ordered_collection(
                DB.activities,
                q=q,
                cursor=request.args.get("cursor"),
                map_func=lambda doc: activity_from_doc(doc, embed=True),
                col_name="outbox",
            )
        )

    # Handle POST request
    try:
        api._api_required()
    except BadSignature:
        abort(401)

    data = request.get_json(force=True)
    app.logger.debug(data)
    activity = ap.parse_activity(data)
    activity_id = tasks.post_to_outbox(activity)

    return Response(status=201, headers={"Location": activity_id})


@app.route("/outbox/<item_id>")
def outbox_detail(item_id):
    doc = DB.activities.find_one(
        {"box": Box.OUTBOX.value, "remote_id": back.activity_url(item_id)}
    )
    if not doc:
        abort(404)

    if doc["meta"].get("deleted", False):
        obj = ap.parse_activity(doc["activity"])
        resp = jsonify(**obj.get_tombstone().to_dict())
        resp.status_code = 410
        return resp
    return jsonify(**activity_from_doc(doc))


@app.route("/outbox/<item_id>/activity")
def outbox_activity(item_id):
    data = DB.activities.find_one(
        {"box": Box.OUTBOX.value, "remote_id": back.activity_url(item_id)}
    )
    if not data:
        abort(404)
    obj = activity_from_doc(data)
    if data["meta"].get("deleted", False):
        obj = ap.parse_activity(data["activity"])
        resp = jsonify(**obj.get_object().get_tombstone().to_dict())
        resp.status_code = 410
        return resp

    if obj["type"] != ActivityType.CREATE.value:
        abort(404)
    return jsonify(**obj["object"])


@app.route("/outbox/<item_id>/replies")
def outbox_activity_replies(item_id):
    if not is_api_request():
        abort(404)
    data = DB.activities.find_one(
        {
            "box": Box.OUTBOX.value,
            "remote_id": back.activity_url(item_id),
            "meta.deleted": False,
        }
    )
    if not data:
        abort(404)
    obj = ap.parse_activity(data["activity"])
    if obj.ACTIVITY_TYPE != ActivityType.CREATE:
        abort(404)

    q = {
        "meta.deleted": False,
        "type": ActivityType.CREATE.value,
        "activity.object.inReplyTo": obj.get_object().id,
    }

    return jsonify(
        **activitypub.build_ordered_collection(
            DB.activities,
            q=q,
            cursor=request.args.get("cursor"),
            map_func=lambda doc: doc["activity"]["object"],
            col_name=f"outbox/{item_id}/replies",
            first_page=request.args.get("page") == "first",
        )
    )


@app.route("/outbox/<item_id>/likes")
def outbox_activity_likes(item_id):
    if not is_api_request():
        abort(404)
    data = DB.activities.find_one(
        {
            "box": Box.OUTBOX.value,
            "remote_id": back.activity_url(item_id),
            "meta.deleted": False,
        }
    )
    if not data:
        abort(404)
    obj = ap.parse_activity(data["activity"])
    if obj.ACTIVITY_TYPE != ActivityType.CREATE:
        abort(404)

    q = {
        "meta.undo": False,
        "type": ActivityType.LIKE.value,
        "$or": [
            {"activity.object.id": obj.get_object().id},
            {"activity.object": obj.get_object().id},
        ],
    }

    return jsonify(
        **activitypub.build_ordered_collection(
            DB.activities,
            q=q,
            cursor=request.args.get("cursor"),
            map_func=lambda doc: remove_context(doc["activity"]),
            col_name=f"outbox/{item_id}/likes",
            first_page=request.args.get("page") == "first",
        )
    )


@app.route("/outbox/<item_id>/shares")
def outbox_activity_shares(item_id):
    if not is_api_request():
        abort(404)
    data = DB.activities.find_one(
        {
            "box": Box.OUTBOX.value,
            "remote_id": back.activity_url(item_id),
            "meta.deleted": False,
        }
    )
    if not data:
        abort(404)
    obj = ap.parse_activity(data["activity"])
    if obj.ACTIVITY_TYPE != ActivityType.CREATE:
        abort(404)

    q = {
        "meta.undo": False,
        "type": ActivityType.ANNOUNCE.value,
        "$or": [
            {"activity.object.id": obj.get_object().id},
            {"activity.object": obj.get_object().id},
        ],
    }

    return jsonify(
        **activitypub.build_ordered_collection(
            DB.activities,
            q=q,
            cursor=request.args.get("cursor"),
            map_func=lambda doc: remove_context(doc["activity"]),
            col_name=f"outbox/{item_id}/shares",
            first_page=request.args.get("page") == "first",
        )
    )


@app.route("/inbox", methods=["GET", "POST"])
def inbox():
    if request.method == "GET":
        if not is_api_request():
            abort(404)
        try:
            api._api_required()
        except BadSignature:
            abort(404)

        return jsonify(
            **activitypub.build_ordered_collection(
                DB.activities,
                q={"meta.deleted": False, "box": Box.INBOX.value},
                cursor=request.args.get("cursor"),
                map_func=lambda doc: remove_context(doc["activity"]),
                col_name="inbox",
            )
        )

    data = request.get_json(force=True)
    logger.debug(f"req_headers={request.headers}")
    logger.debug(f"raw_data={data}")
    try:
        if not verify_request(
            request.method, request.path, request.headers, request.data
        ):
            raise Exception("failed to verify request")
    except Exception:
        logger.exception(
            "failed to verify request, trying to verify the payload by fetching the remote"
        )
        try:
            data = get_backend().fetch_iri(data["id"])
        except ActivityGoneError:
            # XXX Mastodon sends Delete activities that are not dereferencable, it's the actor url with #delete
            # appended, so an `ActivityGoneError` kind of ensure it's "legit"
            if data["type"] == ActivityType.DELETE.value and data["id"].startswith(
                data["object"]
            ):
                logger.info(f"received a Delete for an actor {data!r}")
                if get_backend().inbox_check_duplicate(MY_PERSON, data["id"]):
                    # The activity is already in the inbox
                    logger.info(f"received duplicate activity {data!r}, dropping it")

                DB.activities.insert_one(
                    {
                        "box": Box.INBOX.value,
                        "activity": data,
                        "type": _to_list(data["type"]),
                        "remote_id": data["id"],
                        "meta": {"undo": False, "deleted": False},
                    }
                )
                # TODO(tsileo): write the callback the the delete external actor event
                return Response(status=201)
        except Exception:
            logger.exception(f'failed to fetch remote id at {data["id"]}')
            return Response(
                status=422,
                headers={"Content-Type": "application/json"},
                response=json.dumps(
                    {
                        "error": "failed to verify request (using HTTP signatures or fetching the IRI)"
                    }
                ),
            )
    activity = ap.parse_activity(data)
    logger.debug(f"inbox activity={activity}/{data}")
    tasks.post_to_inbox(activity)

    return Response(status=201)


@app.route("/followers")
def followers():
    q = {"box": Box.INBOX.value, "type": ActivityType.FOLLOW.value, "meta.undo": False}

    if is_api_request():
        return jsonify(
            **activitypub.build_ordered_collection(
                DB.activities,
                q=q,
                cursor=request.args.get("cursor"),
                map_func=lambda doc: doc["activity"]["actor"],
                col_name="followers",
            )
        )

    raw_followers, older_than, newer_than = paginated_query(DB.activities, q)
    followers = []
    for doc in raw_followers:
        try:
            followers.append(doc["meta"]["actor"])
        except Exception:
            pass
    return render_template(
        "followers.html",
        followers_data=followers,
        older_than=older_than,
        newer_than=newer_than,
    )


@app.route("/following")
def following():
    q = {"box": Box.OUTBOX.value, "type": ActivityType.FOLLOW.value, "meta.undo": False}

    if is_api_request():
        return jsonify(
            **activitypub.build_ordered_collection(
                DB.activities,
                q=q,
                cursor=request.args.get("cursor"),
                map_func=lambda doc: doc["activity"]["object"],
                col_name="following",
            )
        )

    if config.HIDE_FOLLOWING and not session.get("logged_in", False):
        abort(404)

    following, older_than, newer_than = paginated_query(DB.activities, q)
    following = [(doc["remote_id"], doc["meta"]["object"]) for doc in following]
    return render_template(
        "following.html",
        following_data=following,
        older_than=older_than,
        newer_than=newer_than,
    )


@app.route("/tags/<tag>")
def tags(tag):
    if not DB.activities.count(
        {
            "box": Box.OUTBOX.value,
            "activity.object.tag.type": "Hashtag",
            "activity.object.tag.name": "#" + tag,
        }
    ):
        abort(404)
    if not is_api_request():
        return render_template(
            "tags.html",
            tag=tag,
            outbox_data=DB.activities.find(
                {
                    "box": Box.OUTBOX.value,
                    "type": ActivityType.CREATE.value,
                    "meta.deleted": False,
                    "activity.object.tag.type": "Hashtag",
                    "activity.object.tag.name": "#" + tag,
                }
            ),
        )
    q = {
        "box": Box.OUTBOX.value,
        "meta.deleted": False,
        "meta.undo": False,
        "type": ActivityType.CREATE.value,
        "activity.object.tag.type": "Hashtag",
        "activity.object.tag.name": "#" + tag,
    }
    return jsonify(
        **activitypub.build_ordered_collection(
            DB.activities,
            q=q,
            cursor=request.args.get("cursor"),
            map_func=lambda doc: doc["activity"]["object"]["id"],
            col_name=f"tags/{tag}",
        )
    )


@app.route("/featured")
def featured():
    if not is_api_request():
        abort(404)
    q = {
        "box": Box.OUTBOX.value,
        "type": ActivityType.CREATE.value,
        "meta.deleted": False,
        "meta.undo": False,
        "meta.pinned": True,
    }
    data = [clean_activity(doc["activity"]["object"]) for doc in DB.activities.find(q)]
    return jsonify(**activitypub.simple_build_ordered_collection("featured", data))


@app.route("/liked")
def liked():
    if not is_api_request():
        q = {
            "box": Box.OUTBOX.value,
            "type": ActivityType.LIKE.value,
            "meta.deleted": False,
            "meta.undo": False,
        }

        liked, older_than, newer_than = paginated_query(DB.activities, q)

        return render_template(
            "liked.html", liked=liked, older_than=older_than, newer_than=newer_than
        )

    q = {"meta.deleted": False, "meta.undo": False, "type": ActivityType.LIKE.value}
    return jsonify(
        **activitypub.build_ordered_collection(
            DB.activities,
            q=q,
            cursor=request.args.get("cursor"),
            map_func=lambda doc: doc["activity"]["object"],
            col_name="liked",
        )
    )


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        directory=os.path.join(app.root_path, 'static'),
        filename='favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )
