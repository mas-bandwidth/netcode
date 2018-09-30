FROM phusion/baseimage:0.9.18

CMD ["/sbin/my_init"]

WORKDIR /app

RUN apt-get -y update && apt-get install -y wget make g++ dh-autoreconf pkg-config valgrind

RUN wget https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz && \
    tar -zxvf libsodium-1.0.16.tar.gz && \
    cd libsodium-1.0.16 && \
    ./configure && \
    make && make check && \
    make install && \
    cd .. && \
    rm -rf libsodium* && \
    ldconfig

RUN wget https://github.com/premake/premake-core/releases/download/v5.0.0-alpha10/premake-5.0.0-alpha10-linux.tar.gz && \ 
    tar -zxvf premake-*.tar.gz && \
    rm premake-*.tar.gz && \
    mv premake5 /usr/local/bin

ADD netcode.io /app/netcode.io

RUN cd netcode.io && find . -exec touch {} \; && premake5 gmake && make -j32 test && cp ./bin/* /app

CMD [ "valgrind", "--tool=memcheck", "--leak-check=yes", "--show-reachable=yes", "--num-callers=20", "--track-fds=yes", "--track-origins=yes", "./test" ]

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
