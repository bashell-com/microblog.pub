from flask import current_app
from config import DB


def _build_thread(data, include_children=True):
    data["_requested"] = True
    current_app.logger.debug(data)
    root_id = data["meta"].get("thread_root_parent", data["activity"]["object"]["id"])

    query = {
        "$or": [
            {"meta.thread_root_parent": root_id, "type": "Create"},
            {"activity.object.id": root_id},
        ]
    }
    if data["activity"]["object"].get("inReplyTo"):
        query["$or"].append(
            {"activity.object.id": data["activity"]["object"]["inReplyTo"]}
        )

    # Fetch the root replies, and the children
    replies = [data] + list(DB.activities.find(query))
    replies = sorted(replies, key=lambda d: d["activity"]["object"]["published"])
    # Index all the IDs in order to build a tree
    idx = {}
    replies2 = []
    for rep in replies:
        rep_id = rep["activity"]["object"]["id"]
        if rep_id in idx:
            continue
        idx[rep_id] = rep.copy()
        idx[rep_id]["_nodes"] = []
        replies2.append(rep)

    # Build the tree
    for rep in replies2:
        rep_id = rep["activity"]["object"]["id"]
        if rep_id == root_id:
            continue
        reply_of = rep["activity"]["object"]["inReplyTo"]
        try:
            idx[reply_of]["_nodes"].append(rep)
        except KeyError:
            current_app.logger.info(f"{reply_of} is not there! skipping {rep}")

    # Flatten the tree
    thread = []

    def _flatten(node, level=0):
        node["_level"] = level
        thread.append(node)

        for snode in sorted(
            idx[node["activity"]["object"]["id"]]["_nodes"],
            key=lambda d: d["activity"]["object"]["published"],
        ):
            _flatten(snode, level=level + 1)

    try:
        _flatten(idx[root_id])
    except KeyError:
        current_app.logger.info(f"{root_id} is not there! skipping")

    return thread
