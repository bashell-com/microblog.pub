from bson.objectid import ObjectId
from flask import request


def paginated_query(db, q, limit=25, sort_key="_id"):
    older_than = newer_than = None
    query_sort = -1
    first_page = not request.args.get("older_than") and not request.args.get(
        "newer_than"
    )

    query_older_than = request.args.get("older_than")
    query_newer_than = request.args.get("newer_than")

    if query_older_than:
        q["_id"] = {"$lt": ObjectId(query_older_than)}
    elif query_newer_than:
        q["_id"] = {"$gt": ObjectId(query_newer_than)}
        query_sort = 1

    outbox_data = list(db.find(q, limit=limit + 1).sort(sort_key, query_sort))
    outbox_len = len(outbox_data)
    outbox_data = sorted(
        outbox_data[:limit], key=lambda x: str(x[sort_key]), reverse=True
    )

    if query_older_than:
        newer_than = str(outbox_data[0]["_id"])
        if outbox_len == limit + 1:
            older_than = str(outbox_data[-1]["_id"])
    elif query_newer_than:
        older_than = str(outbox_data[-1]["_id"])
        if outbox_len == limit + 1:
            newer_than = str(outbox_data[0]["_id"])
    elif first_page and outbox_len == limit + 1:
        older_than = str(outbox_data[-1]["_id"])

    return outbox_data, older_than, newer_than
