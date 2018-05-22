FROM pypy:2-5.9.0

RUN mkdir -p /app
ADD . /app
RUN chmod +x /app/entrypoint.sh

WORKDIR /app
ENV PATH=$PATH:/root/.cargo/bin

RUN \
    apt-get update && \
    apt-get install -y -qq libexpat1-dev gcc libssl-dev libffi-dev libjemalloc1 && \
    curl https://sh.rustup.rs | sh -s -- -y && \
    make clean && \
    WITH_RUST=release pip install -r requirements.txt && \
    pypy setup.py develop && \
    cd autopush_rs && \
    cargo clean && \
    rustup self uninstall -y

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["autopush"]
