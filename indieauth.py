import binascii
from datetime import datetime
import json
import os
from urllib.parse import urlencode

from flask import Response
from flask import abort
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
import flask
from itsdangerous import BadSignature
import mf2py
import pymongo

from config import DB
from config import JWT
from utils.login import login_required

blueprint = flask.Blueprint('indieauth', __name__, template_folder='templates')


def build_auth_resp(payload):
    if request.headers.get("Accept") == "application/json":
        return Response(
            status=200,
            headers={"Content-Type": "application/json"},
            response=json.dumps(payload),
        )
    return Response(
        status=200,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        response=urlencode(payload),
    )


def _get_prop(props, name, default=None):
    if name in props:
        items = props.get(name)
        if isinstance(items, list):
            return items[0]
        return items
    return default


def get_client_id_data(url):
    data = mf2py.parse(url=url)
    for item in data["items"]:
        if "h-x-app" in item["type"] or "h-app" in item["type"]:
            props = item.get("properties", {})
            current_app.logger.debug(props)
            return dict(
                logo=_get_prop(props, "logo"),
                name=_get_prop(props, "name"),
                url=_get_prop(props, "url"),
            )
    return dict(logo=None, name=url, url=url)


@blueprint.route("/indieauth/flow", methods=["POST"])
@login_required
def indieauth_flow():
    auth = dict(
        scope=" ".join(request.form.getlist("scopes")),
        me=request.form.get("me"),
        client_id=request.form.get("client_id"),
        state=request.form.get("state"),
        redirect_uri=request.form.get("redirect_uri"),
        response_type=request.form.get("response_type"),
    )

    code = binascii.hexlify(os.urandom(8)).decode("utf-8")
    auth.update(code=code, verified=False)
    current_app.logger.debug(auth)
    if not auth["redirect_uri"]:
        abort(500)

    DB.indieauth.insert_one(auth)

    # FIXME(tsileo): fetch client ID and validate redirect_uri
    red = f'{auth["redirect_uri"]}?code={code}&state={auth["state"]}&me={auth["me"]}'
    return redirect(red)


# @blueprint.route('/indieauth', methods=['GET', 'POST'])
def indieauth_endpoint():
    if request.method == "GET":
        if not session.get("logged_in"):
            return redirect(url_for("admin_login", next=request.url))

        me = request.args.get("me")
        # FIXME(tsileo): ensure me == ID
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        state = request.args.get("state", "")
        response_type = request.args.get("response_type", "id")
        scope = request.args.get("scope", "").split()

        current_app.logger.debug("STATE", state)
        return render_template(
            "indieauth_flow.html",
            client=get_client_id_data(client_id),
            scopes=scope,
            redirect_uri=redirect_uri,
            state=state,
            response_type=response_type,
            client_id=client_id,
            me=me,
        )

    # Auth verification via POST
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")

    auth = DB.indieauth.find_one_and_update(
        {
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        },  # },  #  , 'verified': False},
        {"$set": {"verified": True}},
        sort=[("_id", pymongo.DESCENDING)],
    )
    current_app.logger.debug(auth)
    current_app.logger.debug(code, redirect_uri, client_id)

    if not auth:
        abort(403)
        return

    session["logged_in"] = True
    me = auth["me"]
    state = auth["state"]
    scope = " ".join(auth["scope"])
    current_app.logger.debug("STATE", state)
    return build_auth_resp({"me": me, "state": state, "scope": scope})


@blueprint.route("/token", methods=["GET", "POST"])
def token_endpoint():
    if request.method == "POST":
        code = request.form.get("code")
        me = request.form.get("me")
        redirect_uri = request.form.get("redirect_uri")
        client_id = request.form.get("client_id")

        auth = DB.indieauth.find_one(
            {
                "code": code,
                "me": me,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            }
        )
        if not auth:
            abort(403)
        scope = " ".join(auth["scope"])
        payload = dict(
            me=me, client_id=client_id, scope=scope, ts=datetime.now().timestamp()
        )
        token = JWT.dumps(payload).decode("utf-8")

        return build_auth_resp({"me": me, "scope": scope, "access_token": token})

    # Token verification
    token = request.headers.get("Authorization").replace("Bearer ", "")
    try:
        payload = JWT.loads(token)
    except BadSignature:
        abort(403)

    # TODO(tsileo): handle expiration

    return build_auth_resp(
        {
            "me": payload["me"],
            "scope": payload["scope"],
            "client_id": payload["client_id"],
        }
    )
