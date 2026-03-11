FROM debian:bookworm AS builder

RUN apt-get -o Acquire::AllowInsecureRepositories=true \
    -o Acquire::AllowDowngradeToInsecureRepositories=true update \
    && apt-get install -y --allow-unauthenticated --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN curl -fsSLO https://nginx.org/download/nginx-1.26.3.tar.gz
RUN tar -xzf nginx-1.26.3.tar.gz

COPY nginx-module/ /module/

WORKDIR /build/nginx-1.26.3
RUN ./configure --with-compat --add-dynamic-module=/module
RUN make modules

FROM nginx:1.26.3

COPY --from=builder /build/nginx-1.26.3/objs/ngx_http_neh_module.so /etc/nginx/modules/
COPY nginx/nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /var/log/neh
