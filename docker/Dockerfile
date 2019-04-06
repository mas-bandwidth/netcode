FROM phusion/baseimage:0.9.18

CMD ["/sbin/my_init"]

WORKDIR /app

RUN apt-get -y update && apt-get install -y wget make g++ dh-autoreconf pkg-config unzip

RUN curl -L -O https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz && \
    tar xf libsodium-*.tar.gz && \
    cd libsodium-* && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf libsodium-* && \
    ldconfig

RUN curl -L -O https://github.com/premake/premake-core/releases/download/v5.0.0-alpha13/premake-5.0.0-alpha13-src.zip && \
    unzip premake-*.zip && \
    cd premake-* && \
    cd build/gmake.unix && \
    make && \
    mv ../../bin/release/premake5 /usr/local/bin && \
    cd ../../../ && \
    rm -rf premake-*

ADD netcode.io /app/netcode.io

RUN cd netcode.io && find . -exec touch {} \; && premake5 gmake && make -j32 test client server client_server config=release_x64 && cp ./bin/* /app

EXPOSE 40000

ENTRYPOINT ./server

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
