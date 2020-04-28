#!/bin/bash

source ~/Env/ublog/bin/activate

export MICROBLOGPUB_AMQP_BROKER=pyamqp://ublog:ublog@127.0.0.1/ublog
export MICROBLOGPUB_MONGODB_HOST=127.0.0.1:27017

celery worker -l info -A tasks

