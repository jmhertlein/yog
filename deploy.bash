#!/bin/bash

set -x
set -e

rm -r ./dist/ || true
pipenv run python3 setup.py sdist bdist_wheel
pipenv run twine upload dist/*
