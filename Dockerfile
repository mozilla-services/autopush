FROM pypy:2

RUN mkdir -p /app
ADD . /app

WORKDIR /app

RUN \
    apt-get install -y -qq libexpat1-dev gcc libssl-dev libffi-dev && \
    make clean && \
    pip install -r requirements.txt && \
    pypy setup.py develop

CMD ["autopush"]
