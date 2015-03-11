# Mozilla AutoPush Server

# VERSION    0.1

# Extend base debian
FROM stackbrew/debian:wheezy

MAINTAINER Ben Bangert <bbangert@mozilla.com>

# It's nice to have some newer packages
RUN echo "deb http://ftp.debian.org/debian sid main" >> /etc/apt/sources.list

RUN mkdir -p /home/autopush
ADD . /home/autopush/

WORKDIR /home/autopush

RUN \
    apt-get update; \
    apt-get install -y -qq make wget bzip2 libexpat1-dev gcc libssl-dev libffi-dev; \
    make clean; \
    make; \
    apt-get remove -y -qq make wget bzip2 libexpat1-dev gcc libssl-dev libffi-dev; \
    apt-get install -y -qq libexpat1 libssl1.0.0 libffi6; \
    apt-get autoremove -y -qq; \
    apt-get clean -y
# End run

CMD ["./bin/autopush"]
