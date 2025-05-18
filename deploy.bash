#!/bin/bash

set -x
set -e

rm -r ./dist/ || true
rm -r ./build/ || true
#pipenv run python3 setup.py sdist bdist_wheel
poetry install --with dev
poetry build
poetry publish

rm -r ./build/ || true
rm -r ./dist/ || true
rm -r yog.egg-info || true
