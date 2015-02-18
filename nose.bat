nosetests -v --with-coverage --cover-inclusive --cover-erase --cover-html --cover-html-dir=./coverage --cover-package=gglsbl --with-html-report --html-output-file ./coverage/report.html
chrome  --new-window
chrome ./coverage/index.html
chrome ./coverage/report.html