FROM alpine:latest

ARG CADDY_VERSION="2.7.6"
ARG HTTP_PREFIX="/vpn/"
ARG ROUTE="fde3:25fb:7f6c::/48"
ARG POOL="fde3:25fb:7f6c:1::/64"
ARG ENDPOINT="vpn.example.com"
ARG INTERFACE="wg0"

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-setuptools \
    curl

RUN curl -LO "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz" \
    && tar -xzf caddy_${CADDY_VERSION}_linux_amd64.tar.gz -C /usr/local/bin \
    && rm caddy_*.tar.gz \
    && chmod +x /usr/local/bin/caddy \
    && caddy version

RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    python3-dev \
    && pip install --no-cache-dir wgnlpy \
    && apk del .build-deps

COPY Caddyfile /etc/caddy/Caddyfile
COPY autowg.py server.py /app/

WORKDIR /app
EXPOSE 80

CMD ["sh", "-c", "caddy run --config /etc/caddy/Caddyfile & python3 server.py --http-prefix ${HTTP_PREFIX} --route ${ROUTE} --pool ${POOL} --endpoint ${ENDPOINT} ${INTERFACE}"]
