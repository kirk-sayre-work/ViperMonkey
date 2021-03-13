FROM pypy:2

WORKDIR /opt

COPY . ./ViperMonkey

RUN apt update -yqq && \
    apt install -yqq --no-install-recommends \
        ca-certificates \
        gcc \
        libc-dev \
        libssl-dev

RUN cd ViperMonkey && \
    pip install -U -r requirements.txt && \
    pip install pyparsing && \
    apt remove -y gcc libc-dev libssl-dev unzip wget && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc && \
    rm -rf /usr/local/share/man /var/cache/debconf/*-old

WORKDIR /malware
CMD [ "bash" ]
