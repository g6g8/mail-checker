
all:


build:
	docker build --progress plain --tag mailservercheck .

run:
	docker run --rm \
	    -e MAILSERVER=$$MAILSERVER \
	    -e PUSHOVER_TOKEN=$$PUSHOVER_TOKEN \
	    -e PUSHOVER_USER=$$PUSHOVER_USER \
	    mailservercheck \
	    mailserver-check.py
