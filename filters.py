from datetime import datetime
from datetime import timedelta
from datetime import timezone
from hashlib import sha1
from typing import Dict
from typing import Optional
from typing import Tuple
import urllib
from urllib.parse import urlparse

import bleach
from dateutil import parser
from flask import current_app
import flask
from html2text import html2text
from langdetect import DetectorFactory
import langdetect
from little_boxes import activitypub as ap
from little_boxes.activitypub import _to_list
from little_boxes.activitypub import get_backend
from little_boxes.errors import ActivityGoneError
from little_boxes.errors import ActivityNotFoundError
from similar_text import similar_text
import timeago
from yandex.Translater import Translater, TranslaterLang

from config import CDN_URL
from config import DB
from config import ID
from config import MEDIA_CACHE
from config import SIMILARITY_THRESHOLD
from config import TIMEZONE
from config import YANDEX_TRANSLATE_API, NO_TRANSLATE, TARGET_LANG
from utils.emoji import flexmoji
from utils.media import Kind

blueprint = flask.Blueprint('filters', __name__, template_folder='templates')

_GRIDFS_CACHE: Dict[Tuple[Kind, str, Optional[int]], str] = {}

# HTML/templates helper
ALLOWED_TAGS = [
    "a",
    "abbr",
    "acronym",
    "b",
    "br",
    "blockquote",
    "code",
    "pre",
    "em",
    "i",
    "li",
    "ol",
    "strong",
    "ul",
    "span",
    "div",
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
]


def _clean_html(html):
    try:
        return bleach.clean(html, tags=ALLOWED_TAGS)
    except:
        return ""


def _get_file_url(url, size, kind):
    k = (kind, url, size)
    cached = _GRIDFS_CACHE.get(k)
    if cached:
        return CDN_URL + cached if cached.startswith('/') else cached

    doc = MEDIA_CACHE.get_file(url, size, kind)
    if doc:
        u = f"/media/{str(doc._id)}"
        _GRIDFS_CACHE[k] = u
        return CDN_URL + u if u.startswith('/') else u

    # MEDIA_CACHE.cache(url, kind)
    current_app.logger.error(f"cache not available for {url}/{size}/{kind}")
    return url


@blueprint.app_template_filter()
def remove_mongo_id(dat):
    if isinstance(dat, list):
        return [remove_mongo_id(item) for item in dat]
    if "_id" in dat:
        dat["_id"] = str(dat["_id"])
    for k, v in dat.items():
        if isinstance(v, dict):
            dat[k] = remove_mongo_id(dat[k])
    return dat


@blueprint.app_template_filter()
def get_video_link(data):
    for link in data:
        if link.get("mimeType", "").startswith("video/"):
            return link.get("href")
    return None


@blueprint.app_template_filter()
def get_actor_icon_url(url, size):
    return _get_file_url(url, size, Kind.ACTOR_ICON)


@blueprint.app_template_filter()
def get_attachment_url(url, size):
    return _get_file_url(url, size, Kind.ATTACHMENT)


@blueprint.app_template_filter()
def get_og_image_url(url, size=100):
    try:
        return _get_file_url(url, size, Kind.OG_IMAGE)
    except Exception:
        return ""


@blueprint.app_template_filter()
def permalink_id(val):
    return str(hash(val))


@blueprint.app_template_filter()
def quote_plus(t):
    return urllib.parse.quote_plus(t)


@blueprint.app_template_filter()
def is_from_outbox(t):
    return t.startswith(ID)


@blueprint.app_template_filter()
def clean(html):
    return _clean_html(html)


@blueprint.app_template_filter()
def emojize(html):
    return flexmoji(html)


@blueprint.app_template_filter()
def html2plaintext(body):
    return html2text(body)


@blueprint.app_template_filter()
def domain(url):
    return urlparse(url).netloc


@blueprint.app_template_filter()
def url_or_id(d):
    if isinstance(d, dict):
        if ("url" in d) and isinstance(d["url"], str):
            return d["url"]
        else:
            return d["id"]
    return ""


@blueprint.app_template_filter()
def get_url(u):
    current_app.logger.debug(f"GET_URL({u!r})")
    if isinstance(u, list):
        for l in u:
            if l.get("mimeType") == "text/html":
                u = l
    if isinstance(u, dict):
        return u["href"]
    elif isinstance(u, str):
        return u
    else:
        return u


@blueprint.app_template_filter()
def get_actor(url):
    if not url:
        return None
    if isinstance(url, list):
        url = url[0]
    if isinstance(url, dict):
        url = url.get("id")
    current_app.logger.debug(f"GET_ACTOR {url}")
    try:
        return get_backend().fetch_iri(url)
    except (ActivityNotFoundError, ActivityGoneError):
        return f"Deleted<{url}>"
    except Exception as exc:
        return f"Error<{url}/{exc!r}>"


@blueprint.app_template_filter()
def format_time(val):
    if val:
        dt = parser.parse(val)
        tz = timedelta(hours=TIMEZONE)
        if TIMEZONE == 0:
            tz_name = " UTC"
        elif TIMEZONE > 0:
            tz_name = f" GMT+{TIMEZONE}"
        else:
            tz_name = f" GMT{TIMEZONE}"
        return datetime.strftime(dt + tz, "%b %d, %Y, %H:%M:%S") + tz_name
    return val


@blueprint.app_template_filter()
def format_timeago(val):
    if val:
        dt = parser.parse(val)
        return timeago.format(dt, datetime.now(timezone.utc))
    return val


@blueprint.app_template_filter()
def has_type(doc, _types):
    for _type in _to_list(_types):
        if _type in _to_list(doc["type"]):
            return True
    return False


@blueprint.app_template_filter()
def has_actor_type(doc):
    for t in ap.ACTOR_TYPES:
        if has_type(doc, t.value):
            return True
    return False


def _is_img(filename):
    filename = filename.lower()
    if (
        filename.endswith(".png")
        or filename.endswith(".jpg")
        or filename.endswith(".jpeg")
        or filename.endswith(".gif")
        or filename.endswith(".svg")
    ):
        return True
    return False


@blueprint.app_template_filter()
def not_only_imgs(attachment):
    for a in attachment:
        if isinstance(a, dict) and not _is_img(a["url"]):
            return True
        if isinstance(a, str) and not _is_img(a):
            return True
    return False


@blueprint.app_template_filter()
def is_img(filename):
    return _is_img(filename)


@blueprint.app_template_filter()
def translate(html):
    if not html.strip() or not YANDEX_TRANSLATE_API:
        return html
    translated_html = ''
    detected_lang = ''
    detected_prob = 0
    similar = 200
    html_hash = sha1(html.encode()).hexdigest()
    cache = DB.translate.find_one({'hash': html_hash, 'target_lang': TARGET_LANG})
    if cache:
        detected_lang = cache['detected_lang']
        detected_prob = cache['detected_prob']
        translated_html = cache['translated_html']
        similar = cache['similar']
        if detected_lang in NO_TRANSLATE:
            return html
        current_app.logger.debug('translation cache HIT')
        current_app.logger.debug(f'cached detected language {detected_lang}:{detected_prob}')
        current_app.logger.debug(f'cached similarity {similar}%')
    else:
        current_app.logger.debug('translation cache MISS')
        clean_html = bleach.clean(html, tags=ALLOWED_TAGS)
        text = html2text(clean_html)
        try:
            langs = langdetect.detect_langs(text)
        except:
            current_app.logger.debug('cannot detect languages on langdetect')
        else:
            for lang in langs:
                if lang.prob > detected_prob:
                    detected_lang = lang.lang
                    detected_prob = lang.prob
            current_app.logger.debug(f'detected language {detected_lang}:{detected_prob}')

        DetectorFactory.seed = 0
        tr = Translater()
        tr.set_key(YANDEX_TRANSLATE_API)
        tr.set_to_lang(TARGET_LANG)

        try:
            tr.set_text(html)
        except:
            current_app.logger.debug('cannot set text on yandex')
            return html

        if not detected_lang:
            try:
                detected_lang = tr.detect_lang()
            except:
                current_app.logger.debug('cannot detect language on yandex')
                return html
            else:
                detected_prob = 2.00
                current_app.logger.debug(f'detected language {detected_lang}:{detected_prob}')

        if detected_lang not in NO_TRANSLATE and detected_prob >= 0.95:
            try:
                tr.set_from_lang(detected_lang)
            except TranslaterLang:
                current_app.logger.debug(f'cannot set language {detected_lang} on yandex')
                if detected_prob == 2.00:
                    return html
                try:
                    detected_lang = tr.detect_lang()
                except:
                    current_app.logger.debug('cannot detect language on yandex')
                    return html
                else:
                    try:
                        tr.set_from_lang(detected_lang)
                    except:
                        current_app.logger.debug(f'cannot set language {detected_lang} on yandex')
                        return html

            try:
                translated_html = tr.translate()
            except:
                current_app.logger.debug(f'cannot translate {detected_lang}→{TARGET_LANG} on yandex')
                return html
            else:
                similar = similar_text(html, translated_html)
                DB.translate.update_one(
                    {"hash": html_hash, "target_lang": TARGET_LANG},
                    {"$set": {"detected_lang": detected_lang,
                              "detected_prob": detected_prob,
                              "html": html,
                              "translated_html": translated_html,
                              "similar": similar}},
                    upsert=True,
                )

    reference = (
        '<div style="float:right;">'
        '<a href="https://translate.yandex.com/">Powered by '
        '<span style="color:red;">Y</span>andex.Translate</a>'
        '</div>'
        '<div style="float:right;margin-left:1px;margin-right:1px;">'
        f'[{detected_lang}→{TARGET_LANG}]'
        '</div>'
    )

    if similar < SIMILARITY_THRESHOLD:
        current_app.logger.debug(f'translated html is {similar}% similar to the original')
        return (
            f'{html}<hr/>{reference}'
            '<div style="clear:both;"></div>'
            f'{translated_html}'
            '<div style="clear:both;"></div>'
        )
    else:
        if similar <= 100:
            current_app.logger.debug(f'translated html is {similar}% similar to the original')
            current_app.logger.debug(f'ORIGINAL HTML: {html}')
            current_app.logger.debug(f'TRANSLATED HTML: {translated_html}')
    return html
