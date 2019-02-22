from little_boxes.activitypub import ActivityType

from activitypub import Box
from config import DB


q1 = {"box": Box.OUTBOX.value, "type": ActivityType.FOLLOW.value, "meta.undo": False}
followings = list()  # type: List[str]
for doc in DB.activities.find(q1):
    _id = doc['_id']
    following = doc['activity']['object']
    if following not in followings:
        followings.append(following)
        print(f'following: {following}')
    else:
        DB.activities.delete_one({'_id':_id})
        print(f'duplicate: {following} -- deleted')

q2 = {"box": Box.INBOX.value, "type": ActivityType.FOLLOW.value, "meta.undo": False}
followers = list()  # type: List[str]
for doc in DB.activities.find(q2):
    _id = doc['_id']
    follower = doc['activity']['actor']
    if follower not in followers:
        followers.append(follower)
        print(f'follower: {follower}')
    else:
        DB.activities.delete_one({'_id':_id})
        print(f'duplicate: {follower} -- deleted')

