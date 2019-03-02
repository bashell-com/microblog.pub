#!/bin/sh
/opt/ublog/bin/python -O -c "import config; config.create_indexes()"
/opt/ublog/bin/gunicorn -t 300 -w 2 -k gevent -b 0.0.0.0:5005 --log-level info app:app
