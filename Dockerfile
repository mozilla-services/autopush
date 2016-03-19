# Mozilla AutoPush Server

# VERSION    0.1

# Extend base debian
FROM stackbrew/debian:sid

MAINTAINER Ben Bangert <bbangert@mozilla.com>

RUN mkdir -p /home/autopush
ADD . /home/autopush/

WORKDIR /home/autopush

RUN \
    apt-get update; \
    apt-get install -y -qq make curl wget bzip2 libexpat1-dev gcc git-core libssl1.0.0 libssl-dev libffi-dev; \
    make clean; \
    wget https://bitbucket.org/pypy/pypy/downloads/pypy-5.0.0-linux64.tar.bz2; \
    tar xjvf pypy-5.0.0-linux64.tar.bz2; \
    mv pypy-5.0.0-linux64 pypy; \
    make; \
    apt-get remove -y -qq make curl wget bzip2 libexpat1-dev gcc git-core libssl1.0.0 libssl-dev libffi-dev; \
    apt-get install -y -qq libexpat1 libssl1.0.0 libffi6; \
    apt-get autoremove -y -qq; \
    apt-get clean -y
# End run

CMD ["./pypy/bin/autopush"]
