from flask import current_app
import flask
from little_boxes import activitypub as ap
from little_boxes.activitypub import ActivityType

from activitypub import Box
import activitypub
from config import DB
from config import MEDIA_CACHE
import tasks
from utils.login import login_required
from utils.media import Kind

back = activitypub.MicroblogPubBackend()
ap.use_backend(back)
blueprint = flask.Blueprint('migrations', __name__, template_folder='templates')


@blueprint.route("/migration1_step1")
@login_required
def tmp_migrate():
    for activity in DB.outbox.find():
        activity["box"] = Box.OUTBOX.value
        DB.activities.insert_one(activity)
    for activity in DB.inbox.find():
        activity["box"] = Box.INBOX.value
        DB.activities.insert_one(activity)
    for activity in DB.replies.find():
        activity["box"] = Box.REPLIES.value
        DB.activities.insert_one(activity)
    return "Done"


@blueprint.route("/migration1_step2")
@login_required
def tmp_migrate2():
    # Remove buggy OStatus announce
    DB.activities.remove(
        {"activity.object": {"$regex": f"^tag:"}, "type": ActivityType.ANNOUNCE.value}
    )
    # Cache the object
    for activity in DB.activities.find():
        if (
            activity["box"] == Box.OUTBOX.value
            and activity["type"] == ActivityType.LIKE.value
        ):
            like = ap.parse_activity(activity["activity"])
            obj = like.get_object()
            DB.activities.update_one(
                {"remote_id": like.id},
                {"$set": {"meta.object": obj.to_dict(embed=True)}},
            )
        elif activity["type"] == ActivityType.ANNOUNCE.value:
            announce = ap.parse_activity(activity["activity"])
            obj = announce.get_object()
            DB.activities.update_one(
                {"remote_id": announce.id},
                {"$set": {"meta.object": obj.to_dict(embed=True)}},
            )
    return "Done"


@blueprint.route("/migration2")
@login_required
def tmp_migrate3():
    for activity in DB.activities.find():
        try:
            activity = ap.parse_activity(activity["activity"])
            actor = activity.get_actor()
            if actor.icon:
                MEDIA_CACHE.cache(actor.icon["url"], Kind.ACTOR_ICON)
            if activity.type == ActivityType.CREATE.value:
                for attachment in activity.get_object()._data.get("attachment", []):
                    MEDIA_CACHE.cache(attachment["url"], Kind.ATTACHMENT)
        except Exception:
            current_app.logger.exception("failed")
    return "Done"


@blueprint.route("/migration3")
@login_required
def tmp_migrate4():
    for activity in DB.activities.find(
        {"box": Box.OUTBOX.value, "type": ActivityType.UNDO.value}
    ):
        try:
            activity = ap.parse_activity(activity["activity"])
            if activity.get_object().type == ActivityType.FOLLOW.value:
                DB.activities.update_one(
                    {"remote_id": activity.get_object().id},
                    {"$set": {"meta.undo": True}},
                )
                print(activity.get_object().to_dict())
        except Exception:
            current_app.logger.exception("failed")
    for activity in DB.activities.find(
        {"box": Box.INBOX.value, "type": ActivityType.UNDO.value}
    ):
        try:
            activity = ap.parse_activity(activity["activity"])
            if activity.get_object().type == ActivityType.FOLLOW.value:
                DB.activities.update_one(
                    {"remote_id": activity.get_object().id},
                    {"$set": {"meta.undo": True}},
                )
                print(activity.get_object().to_dict())
        except Exception:
            current_app.logger.exception("failed")
    return "Done"


@blueprint.route("/migration4")
@login_required
def tmp_migrate5():
    for activity in DB.activities.find():
        tasks.cache_actor.delay(activity["remote_id"], also_cache_attachments=False)

    return "Done"


@blueprint.route("/migration5")
@login_required
def tmp_migrate6():
    for activity in DB.activities.find():
        # tasks.cache_actor.delay(activity["remote_id"], also_cache_attachments=False)

        try:
            a = ap.parse_activity(activity["activity"])
            if a.has_type([ActivityType.LIKE, ActivityType.FOLLOW]):
                DB.activities.update_one(
                    {"remote_id": a.id},
                    {
                        "$set": {
                            "meta.object_actor": activitypub._actor_to_meta(
                                a.get_object().get_actor()
                            )
                        }
                    },
                )
        except Exception:
            current_app.logger.exception(f"processing {activity} failed")

    return "Done"
