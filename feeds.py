import json

from flask import Response
import flask

import activitypub

blueprint = flask.Blueprint('feeds', __name__, template_folder='templates')


@blueprint.route("/feed.json")
def json_feed():
    return Response(
        response=json.dumps(
            activitypub.json_feed("/feed.json")
        ),
        headers={"Content-Type": "application/json"},
    )


@blueprint.route("/feed.atom")
def atom_feed():
    return Response(
        response=activitypub.gen_feed().atom_str(),
        headers={"Content-Type": "application/atom+xml"},
    )


@blueprint.route("/feed.rss")
def rss_feed():
    return Response(
        response=activitypub.gen_feed().rss_str(),
        headers={"Content-Type": "application/rss+xml"},
    )
