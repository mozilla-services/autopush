FROM pypy:2-7.3.0

RUN mkdir -p /app
ADD . /app
RUN chmod +x /app/entrypoint.sh

WORKDIR /app
ENV PATH=$PATH:/root/.cargo/bin

RUN \
    apt-get update && \
    apt-get install -y -qq libexpat1-dev gcc libssl-dev libffi-dev libjemalloc2 && \
    make clean && \
    pip install -r requirements.txt && \
    pypy setup.py develop

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["autopush"]
