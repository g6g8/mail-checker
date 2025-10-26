FROM alpine

RUN \
	apk --no-cache add python3 py3-pip \
        && rm -f /usr/lib/python*/EXTERNALL* \
	&& pip install dnspython requests

COPY mailserver-check.py /usr/local/bin/

RUN chmod 755 /usr/local/bin/mail*

CMD [ "/usr/local/bin/mailserver-check.py" ]

