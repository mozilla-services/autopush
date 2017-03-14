FROM pypy:2-5.6.0

RUN mkdir -p /app
ADD . /app

WORKDIR /app

RUN \
    apt-get update && \
    apt-get install -y -qq libexpat1-dev gcc libssl-dev libffi-dev && \
    make clean && \
    pip install -r pypy-requirements.txt && \
    pypy setup.py develop

CMD ["autopush"]
