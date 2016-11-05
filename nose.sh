#!/usr/bin/env bash
rm -r coverage
set -e
nosetests -v --with-coverage  --cover-erase --cover-html --cover-html-dir=./coverage --cover-package=gglsbl3 --with-html-report --html-output-file ./coverage/report.html
chromium-browser  --new-window
chromium-browser ./coverage/index.html
chromium-browser ./coverage/report.html

