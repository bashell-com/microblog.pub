#!/bin/bash

source ~/Env/ublog/bin/activate

export MICROBLOGPUB_AMQP_BROKER=pyamqp://ublog:ublog@127.0.0.1/ublog
export MICROBLOGPUB_MONGODB_HOST=127.0.0.1:27017

python -O -c "import config; config.create_indexes()"
gunicorn -t 300 -w 2 -k gevent -b 0.0.0.0:5005 --log-level info app:app

