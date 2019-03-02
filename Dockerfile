#FROM quay.io/bashell/alpine-python:3
FROM docker.io/jamiehewland/alpine-pypy:3.6

RUN apk add ca-certificates openssl libxml2 libxslt libstdc++ git make \
            libjpeg-turbo openjpeg tiff lcms2 freetype libwebp 

RUN pypy3 -O -m venv /opt/ublog \
 && /opt/ublog/bin/python -O -m pip install --compile --install-option=-O1 --upgrade pip \
 && /opt/ublog/bin/python -O -m pip install --compile --install-option=-O1 --upgrade setuptools

ADD requirements.txt /opt/ublog/requirements.txt

RUN apk add gcc g++ musl-dev libffi-dev openssl-dev libxml2-dev libxslt-dev \
            libjpeg-turbo-dev openjpeg-dev tiff-dev lcms2-dev freetype-dev libwebp-dev zlib-dev \
 && /opt/ublog/bin/python -O -m pip install --compile --install-option=-O1 Cython \
 && /opt/ublog/bin/python -O -m pip install --compile --install-option=-O1 -r /opt/ublog/requirements.txt \
 && sed -i -e 's/python$/python -O/' /opt/ublog/bin/gunicorn \
 && sed -i -e 's/python$/python -O/' /opt/ublog/bin/celery \
 && apk del gcc g++ musl-dev libffi-dev openssl-dev libxml2-dev libxslt-dev \
            libjpeg-turbo-dev openjpeg-dev tiff-dev lcms2-dev freetype-dev libwebp-dev zlib-dev \
 && rm -rf /var/cache/*/*

ADD . /app

WORKDIR /app

VOLUME /app/config
VOLUME /app/static

EXPOSE 5005/tcp

ENV FLASK_APP=app.py

CMD ["./run.sh"]
