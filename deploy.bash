#!/bin/bash

set -x
set -e

rm -r ./dist/
pipenv run python3 setup.py sdist bdist_wheel
ssh pyrepo@cnc mkdir -p /srv/pyrepo.hert/yog
scp ./dist/yog-*.tar.gz pyrepo@cnc:/srv/pyrepo.hert/yog
scp ./dist/yog-*.whl pyrepo@cnc:/srv/pyrepo.hert/yog
