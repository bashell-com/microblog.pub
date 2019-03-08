import base64
from enum import Enum
from gzip import GzipFile
from io import BytesIO
import mimetypes
from typing import Any

from PIL import Image
import gridfs
import piexif
import requests


def load(url, user_agent):
    """Initializes a `PIL.Image` from the URL."""
    with requests.get(url, stream=True,
                      headers={"User-Agent": user_agent}) as resp:
        resp.raise_for_status()
        if not resp.headers.get('content-type').startswith('image/'):
            raise ValueError(
                f"bad content-type {resp.headers.get('content-type')}"
            )

        resp.raw.decode_content = True
        return Image.open(BytesIO(resp.raw.read()))


def info(img):
    """Returns image info dictionary to be used with `PIL.Image.save()`"""
    if not isinstance(img, Image.Image):
        raise TypeError('`img` must be an instance of `PIL.Image.Image`')

    INFO_KEYS = ['duration',
                 'gamma',
                 'icc_profile',
                 'interlace',
                 'loop',
                 'transparency']
    return dict(
        [(key, img.info.get(key)) for key in INFO_KEYS if key in img.info]
    )


def to_data_uri(img):
    out = BytesIO()
    img.save(out, format=img.format)
    out.seek(0)
    data = base64.b64encode(out.read()).decode("utf-8")
    return f"data:{img.get_format_mimetype()};base64,{data}"


class Kind(Enum):
    ATTACHMENT = "attachment"
    ACTOR_ICON = "actor_icon"
    UPLOAD = "upload"
    OG_IMAGE = "og"


class MediaCache(object):
    def __init__(self, gridfs_db: str, user_agent: str) -> None:
        self.fs = gridfs.GridFS(gridfs_db)
        self.user_agent = user_agent

    def cache_og_image(self, url: str) -> None:
        if self.fs.find_one({"url": url, "kind": Kind.OG_IMAGE.value}):
            return
        i = load(url, self.user_agent)
        # Save the original attachment (gzipped)
        i.thumbnail((100, 100))
        with BytesIO() as buf:
            with GzipFile(mode="wb", fileobj=buf) as f1:
                i.save(f1, format=i.format,
                       optimize=True, progressive=True, **info(i))
            buf.seek(0)
            self.fs.put(
                buf,
                url=url,
                size=100,
                content_type=i.get_format_mimetype(),
                kind=Kind.OG_IMAGE.value,
            )

    def cache_attachment(self, url: str) -> None:
        if self.fs.find_one({"url": url, "kind": Kind.ATTACHMENT.value}):
            return
        if (
            url.endswith(".png")
            or url.endswith(".jpg")
            or url.endswith(".jpeg")
            or url.endswith(".gif")
        ):
            i = load(url, self.user_agent)
            # Save the original attachment (gzipped)
            with BytesIO() as buf:
                f1 = GzipFile(mode="wb", fileobj=buf)
                i.save(f1, format=i.format,
                       optimize=True, progressive=True, **info(i))
                f1.close()
                buf.seek(0)
                self.fs.put(
                    buf,
                    url=url,
                    size=None,
                    content_type=i.get_format_mimetype(),
                    kind=Kind.ATTACHMENT.value,
                )
            # Save a thumbnail (gzipped)
            i.thumbnail((720, 720))
            with BytesIO() as buf:
                with GzipFile(mode="wb", fileobj=buf) as f1:
                    i.save(f1, format=i.format,
                           optimize=True, progressive=True, **info(i))
                buf.seek(0)
                self.fs.put(
                    buf,
                    url=url,
                    size=720,
                    content_type=i.get_format_mimetype(),
                    kind=Kind.ATTACHMENT.value,
                )
            return

        # The attachment is not an image, download and save it anyway
        with requests.get(
            url, stream=True, headers={"User-Agent": self.user_agent}
        ) as resp:
            resp.raise_for_status()
            with BytesIO() as buf:
                with GzipFile(mode="wb", fileobj=buf) as f1:
                    for chunk in resp.iter_content():
                        if chunk:
                            f1.write(chunk)
                buf.seek(0)
                self.fs.put(
                    buf,
                    url=url,
                    size=None,
                    content_type=mimetypes.guess_type(url)[0],
                    kind=Kind.ATTACHMENT.value,
                )

    def cache_actor_icon(self, url: str) -> None:
        if self.fs.find_one({"url": url, "kind": Kind.ACTOR_ICON.value}):
            return
        i = load(url, self.user_agent)
        for size in [50, 80]:
            t1 = i.copy()
            t1.thumbnail((size, size))
            with BytesIO() as buf:
                with GzipFile(mode="wb", fileobj=buf) as f1:
                    t1.save(f1, format=i.format,
                            optimize=True, progressive=True, **info(i))
                buf.seek(0)
                self.fs.put(
                    buf,
                    url=url,
                    size=size,
                    content_type=i.get_format_mimetype(),
                    kind=Kind.ACTOR_ICON.value,
                )

    def save_upload(self, obuf: BytesIO, filename: str, max_size: tuple) -> str:
        # Remove EXIF metadata
        if filename.lower().endswith(".jpg") \
        or filename.lower().endswith(".jpeg"):
            obuf.seek(0)
            with BytesIO() as buf2:
                piexif.remove(obuf.getvalue(), buf2)
                obuf.truncate(0)
                obuf.write(buf2.getvalue())

        mtype = mimetypes.guess_type(filename)[0]
        thumbnail_buf = BytesIO()
        if mtype and mtype.startswith('image'):
            i = Image.open(obuf, 'r')
            if (i.width > max_size[0]) or (i.height > max_size[1]):
                i.thumbnail(size=max_size)
                i.save(thumbnail_buf, format=i.format,
                       optimize=True, progressive=True, **info(i))
        obuf.seek(0)
        with BytesIO() as gbuf:
            with GzipFile(mode="wb", fileobj=gbuf) as gzipfile:
                gzipfile.write(thumbnail_buf.getvalue() or obuf.getvalue())

            gbuf.seek(0)
            oid = self.fs.put(
                gbuf,
                content_type=mtype,
                upload_filename=filename,
                kind=Kind.UPLOAD.value,
            )
            return str(oid)

    def cache(self, url: str, kind: Kind) -> None:
        if kind == Kind.ACTOR_ICON:
            self.cache_actor_icon(url)
        elif kind == Kind.OG_IMAGE:
            self.cache_og_image(url)
        else:
            self.cache_attachment(url)

    def get_actor_icon(self, url: str, size: int) -> Any:
        return self.get_file(url, size, Kind.ACTOR_ICON)

    def get_attachment(self, url: str, size: int) -> Any:
        return self.get_file(url, size, Kind.ATTACHMENT)

    def get_file(self, url: str, size: int, kind: Kind) -> Any:
        return self.fs.find_one({"url": url, "size": size, "kind": kind.value})
