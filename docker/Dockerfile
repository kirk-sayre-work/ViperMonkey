FROM pypy:2

WORKDIR /opt

RUN apt update -yqq && \
    apt upgrade -yqq && \
    apt install -yqq --no-install-recommends \
        ca-certificates \
        gcc \
        libc-dev \
        libssl-dev \
        unzip \
        libimage-exiftool-perl \
        wget && \
    wget https://github.com/chezwicker/ViperMonkey/archive/refs/heads/master.zip && \
    unzip master.zip && \
    rm master.zip && \
    mv ViperMonkey-master ViperMonkey && \
    cd ViperMonkey && \
    pip install -U -r requirements.txt && \
    pip install pyparsing && \
    apt remove -y gcc libc-dev libssl-dev unzip wget && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc && \
    rm -rf /usr/local/share/man /var/cache/debconf/*-old

WORKDIR /malware
CMD [ "bash" ]
