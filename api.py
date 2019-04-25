from functools import wraps
from io import BytesIO
import json
import mimetypes

from flask import Response
from flask import abort
from flask import current_app
from flask import jsonify as flask_jsonify
from flask import redirect
from flask import request
from flask import session
import flask
from flask_wtf.csrf import CSRFProtect
from itsdangerous import BadSignature
from little_boxes import activitypub as ap
from little_boxes.activitypub import ActivityType
from little_boxes.activitypub import get_backend
from little_boxes.content_helper import parse_markdown
from little_boxes.errors import ActivityNotFoundError
from little_boxes.errors import NotFromOutboxError
from werkzeug.utils import secure_filename

from activitypub import Box
import activitypub
from config import ADMIN_API_KEY
from config import BASE_URL
from config import CDN_URL
from config import DB
from config import DEBUG_MODE
from config import ID
from config import IMAGE_MAX_SIZE
from config import JWT
from config import ME
from config import MEDIA_CACHE
from config import _drop_db
import tasks
from utils.emoji import flexmoji
from utils.login import login_required

blueprint = flask.Blueprint('api', __name__, template_folder='templates')
csrf = CSRFProtect(current_app)
back = activitypub.MicroblogPubBackend()
ap.use_backend(back)

MY_PERSON = ap.Person(**ME)


def _api_required():
    if session.get("logged_in"):
        if request.method not in ["GET", "HEAD"]:
            # If a standard API request is made with a "login session", it must havw a CSRF token
            csrf.protect()
        return

    # Token verification
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        # IndieAuth token
        token = request.form.get("access_token", "")

    # Will raise a BadSignature on bad auth
    payload = JWT.loads(token)
    current_app.logger.info(f"api call by {payload}")


def api_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            _api_required()
        except BadSignature:
            abort(401)

        return f(*args, **kwargs)

    return decorated_function


@blueprint.route("/api/key")
@login_required
def api_user_key():
    return flask_jsonify(api_key=ADMIN_API_KEY)


def _user_api_arg(key: str, **kwargs):
    """Try to get the given key from the requests, try JSON body, form data and query arg."""
    if request.is_json:
        oid = request.json.get(key)
    else:
        oid = request.args.get(key) or request.form.get(key)

    if not oid:
        if "default" in kwargs:
            current_app.logger.info(f'{key}={kwargs.get("default")}')
            return kwargs.get("default")

        raise ValueError(f"missing {key}")

    current_app.logger.info(f"{key}={oid}")
    return oid


def _user_api_get_note(from_outbox: bool=False):
    oid = _user_api_arg("id")
    current_app.logger.info(f"fetching {oid}")
    try:
        note = ap.parse_activity(get_backend().fetch_iri(oid), expected=ActivityType.NOTE)
    except:
        try:
            note = ap.parse_activity(get_backend().fetch_iri(oid), expected=ActivityType.VIDEO)
        except:
            raise ActivityNotFoundError(
                "Expected Note or Video ActivityType, but got something else"
            )
    if from_outbox and not note.id.startswith(ID):
        raise NotFromOutboxError(
            f"cannot load {note.id}, id must be owned by the server"
        )

    return note


def _user_api_response(**kwargs):
    _redirect = _user_api_arg("redirect", default=None)
    if _redirect:
        return redirect(_redirect)

    resp = flask_jsonify(**kwargs)
    resp.status_code = 201
    return resp


@blueprint.route("/api/note/delete", methods=["POST"])
@api_required
def api_delete():
    """API endpoint to delete a Note activity."""
    note = _user_api_get_note(from_outbox=True)

    delete = ap.Delete(actor=ID, object=ap.Tombstone(id=note.id).to_dict(embed=True))

    delete_id = tasks.post_to_outbox(delete)

    return _user_api_response(activity=delete_id)


@blueprint.route("/api/boost", methods=["POST"])
@api_required
def api_boost():
    note = _user_api_get_note()

    announce = note.build_announce(MY_PERSON)
    announce_id = tasks.post_to_outbox(announce)

    return _user_api_response(activity=announce_id)


@blueprint.route("/api/like", methods=["POST"])
@api_required
def api_like():
    note = _user_api_get_note()

    like = note.build_like(MY_PERSON)
    like_id = tasks.post_to_outbox(like)

    return _user_api_response(activity=like_id)


@blueprint.route("/api/note/pin", methods=["POST"])
@api_required
def api_pin():
    note = _user_api_get_note(from_outbox=True)

    DB.activities.update_one(
        {"activity.object.id": note.id, "box": Box.OUTBOX.value},
        {"$set": {"meta.pinned": True}},
    )

    return _user_api_response(pinned=True)


@blueprint.route("/api/note/unpin", methods=["POST"])
@api_required
def api_unpin():
    note = _user_api_get_note(from_outbox=True)

    DB.activities.update_one(
        {"activity.object.id": note.id, "box": Box.OUTBOX.value},
        {"$set": {"meta.pinned": False}},
    )

    return _user_api_response(pinned=False)


@blueprint.route("/api/undo", methods=["POST"])
@api_required
def api_undo():
    oid = _user_api_arg("id")
    doc = DB.activities.find_one(
        {
            "box": Box.OUTBOX.value,
            "$or": [{"remote_id": back.activity_url(oid)}, {"remote_id": oid}],
        }
    )
    if not doc:
        raise ActivityNotFoundError(f"cannot found {oid}")

    obj = ap.parse_activity(doc.get("activity"))
    # FIXME(tsileo): detect already undo-ed and make this API call idempotent
    undo = obj.build_undo()
    undo_id = tasks.post_to_outbox(undo)

    return _user_api_response(activity=undo_id)


def without_id(l):
    out = []
    for d in l:
        if "_id" in d:
            del d["_id"]
        out.append(d)
    return out


@blueprint.route("/api/debug", methods=["GET", "DELETE"])
@api_required
def api_debug():
    """Endpoint used/needed for testing, only works in DEBUG_MODE."""
    if not DEBUG_MODE:
        return flask_jsonify(message="DEBUG_MODE is off")

    if request.method == "DELETE":
        _drop_db()
        return flask_jsonify(message="DB dropped")

    return flask_jsonify(
        inbox=DB.activities.count({"box": Box.INBOX.value}),
        outbox=DB.activities.count({"box": Box.OUTBOX.value}),
        outbox_data=without_id(DB.activities.find({"box": Box.OUTBOX.value})),
    )


@blueprint.route("/api/new_note", methods=["POST"])
@api_required
def api_new_note():
    source = _user_api_arg("content")
    if not source:
        raise ValueError("missing content")

    _reply, reply = None, None
    try:
        _reply = _user_api_arg("reply")
    except ValueError:
        pass

    content, tags = parse_markdown(source)
    content = flexmoji(content)
    to = request.args.get("to")
    cc = [ID + "/followers"]

    if _reply:
        reply = ap.fetch_remote_activity(_reply)
        cc.append(reply.attributedTo)

    for tag in tags:
        if tag["type"] == "Mention":
            cc.append(tag["href"])

    raw_note = dict(
        attributedTo=MY_PERSON.id,
        cc=list(set(cc)),
        to=[to if to else ap.AS_PUBLIC],
        content=content,
        tag=tags,
        source={"mediaType": "text/markdown", "content": source},
        inReplyTo=reply.id if reply else None,
    )

    if "file" in request.files and request.files["file"].filename:
        file = request.files["file"]
        rfilename = secure_filename(file.filename)
        with BytesIO() as buf:
            file.save(buf)
            oid = MEDIA_CACHE.save_upload(buf, rfilename, IMAGE_MAX_SIZE)
        mtype = mimetypes.guess_type(rfilename)[0]
        url = f"{BASE_URL}/uploads/{oid}/{rfilename}"
        if CDN_URL:
            url = f"{CDN_URL}/uploads/{oid}/{rfilename}"
        raw_note["attachment"] = [
            {
                "mediaType": mtype,
                "name": rfilename,
                "type": "Document",
                "url": url,
            }
        ]

    note = ap.Note(**raw_note)
    create = note.build_create()
    create_id = tasks.post_to_outbox(create)

    return _user_api_response(activity=create_id)


@blueprint.route("/api/stream")
@api_required
def api_stream():
    return Response(
        response=json.dumps(
            activitypub.build_inbox_json_feed("/api/stream", request.args.get("cursor"))
        ),
        headers={"Content-Type": "application/json"},
    )


@blueprint.route("/api/block", methods=["POST"])
@api_required
def api_block():
    actor = _user_api_arg("actor")

    existing = DB.activities.find_one(
        {
            "box": Box.OUTBOX.value,
            "type": ActivityType.BLOCK.value,
            "activity.object": actor,
            "meta.undo": False,
        }
    )
    if existing:
        return _user_api_response(activity=existing["activity"]["id"])

    block = ap.Block(actor=MY_PERSON.id, object=actor)
    block_id = tasks.post_to_outbox(block)

    return _user_api_response(activity=block_id)


@blueprint.route("/api/follow", methods=["POST"])
@api_required
def api_follow():
    actor = _user_api_arg("actor")

    q = {
        "box": Box.OUTBOX.value,
        "type": ActivityType.FOLLOW.value,
        "meta.undo": False,
        "activity.object": actor,
    }

    existing = DB.activities.find_one(q)
    if existing:
        return _user_api_response(activity=existing["activity"]["id"])

    follow = ap.Follow(actor=MY_PERSON.id, object=actor)
    follow_id = tasks.post_to_outbox(follow)

    return _user_api_response(activity=follow_id)
