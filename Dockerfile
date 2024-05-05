FROM debian:bookworm-slim

# runtime dependencies
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
# @system-ca: https://github.com/docker-library/haproxy/pull/216
		ca-certificates \
	; \
	rm -rf /var/lib/apt/lists/*

# roughly, https://salsa.debian.org/haproxy-team/haproxy/-/blob/732b97ae286906dea19ab5744cf9cf97c364ac1d/debian/haproxy.postinst#L5-6
RUN set -eux; \
	groupadd --gid 99 --system haproxy; \
	useradd \
		--gid haproxy \
		--home-dir /var/lib/haproxy \
		--no-create-home \
		--system \
		--uid 99 \
		haproxy \
	; \
	mkdir /var/lib/haproxy
#	chown haproxy:haproxy /var/lib/haproxy

ENV HAPROXY_VERSION 2.9.7
ENV HAPROXY_URL https://www.haproxy.org/download/2.9/src/haproxy-2.9.7.tar.gz
ENV HAPROXY_SHA256 d1a0a56f008a8d2f007bc0c37df6b2952520d1f4dde33b8d3802710e5158c131

# see https://sources.debian.net/src/haproxy/jessie/debian/rules/ for some helpful navigation of the possible "make" arguments
RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update && apt-get install -y --no-install-recommends \
		gcc \
		libc6-dev \
		liblua5.4-dev \
		libpcre2-dev \
		libssl-dev \
		make \
		wget \
	; \
	rm -rf /var/lib/apt/lists/*; \
	\
	wget -O haproxy.tar.gz "$HAPROXY_URL"; \
	echo "$HAPROXY_SHA256 *haproxy.tar.gz" | sha256sum -c; \
	mkdir -p /usr/src/haproxy; \
	tar -xzf haproxy.tar.gz -C /usr/src/haproxy --strip-components=1; \
	rm haproxy.tar.gz; \
	\
	makeOpts=' \
		TARGET=linux-glibc \
		USE_GETADDRINFO=1 \
		USE_LUA=1 LUA_INC=/usr/include/lua5.4 \
		USE_OPENSSL=1 \
		USE_PCRE2=1 USE_PCRE2_JIT=1 \
		USE_PROMEX=1 \
		\
		EXTRA_OBJS=" \
		" \
	'; \
# https://salsa.debian.org/haproxy-team/haproxy/-/commit/53988af3d006ebcbf2c941e34121859fd6379c70
	dpkgArch="$(dpkg --print-architecture)"; \
	case "$dpkgArch" in \
		armel) makeOpts="$makeOpts ADDLIB=-latomic" ;; \
	esac; \
	\
	nproc="$(nproc)"; \
	eval "make -C /usr/src/haproxy -j '$nproc' all $makeOpts"; \
	eval "make -C /usr/src/haproxy install-bin $makeOpts"; \
	\
	mkdir -p /usr/local/etc/haproxy; \
	cp -R /usr/src/haproxy/examples/errorfiles /usr/local/etc/haproxy/errors; \
	rm -rf /usr/src/haproxy; \
	\
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; \
	find /usr/local -type f -executable -exec ldd '{}' ';' \
		| awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
		| sort -u \
		| xargs -r dpkg-query --search \
		| cut -d: -f1 \
		| sort -u \
		| xargs -r apt-mark manual \
	; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	\
# smoke test
	haproxy -v

RUN set -eux; \
        \
        savedAptMark="$(apt-mark showmanual)"; \
        apt-get update && apt-get install -y  \
	curl \
	iproute2 \
	wget \
	certbot \
	procps \
	openssh-server \
	nano; \
	curl https://ssl-config.mozilla.org/ffdhe2048.txt > /usr/local/etc/haproxy/dhparam.pem;\
	sed -i "s/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/g" /etc/ssh/sshd_config; \
	sed -i "s/#ListenAddress ::/ListenAddress ::/g" /etc/ssh/sshd_config; \
	sed -i "s/#PermitRootLogin .*$/PermitRootLogin yes/g" /etc/ssh/sshd_config

# https://www.haproxy.org/download/1.8/doc/management.txt
# "4. Stopping and restarting HAProxy"
# "when the SIGTERM signal is sent to the haproxy process, it immediately quits and all established connections are closed"
# "graceful stop is triggered when the SIGUSR1 signal is sent to the haproxy process"
STOPSIGNAL SIGUSR1

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

RUN echo 'global\n\
	# modern configuration\n\
	ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n\
	ssl-default-bind-options prefer-client-ciphers ssl-min-ver TLSv1.2 no-tls-tickets\n\
\n\
	ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n\
	ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets\n\
\n\
	tune.ssl.default-dh-param 2048\n\
	ssl-dh-param-file /usr/local/etc/haproxy/dhparam.pem\n\
\n\
defaults\n\
        log global\n\
        mode http\n\
        option dontlognull\n\
        timeout connect 5000s\n\
        timeout client  5000s\n\
        timeout server  5000s\n\
\n\
frontend Listen0\n\
        bind *:80'>>/usr/local/etc/haproxy/haproxy.cfg \
&& echo	\#bind *:443 ssl crt /etc/letsencrypt/live/mysite.com/fullchainwkey.pem alpn h2,http/1.1 >>/usr/local/etc/haproxy/haproxy.cfg \
&& echo '\toption http-server-close\n\
	http-request redirect scheme https unless { ssl_fc }\n\
	option forwardfor except 127.0.0.0/8\n\
	# HSTS (63072000 seconds)\n\
	http-response set-header Strict-Transport-Security max-age=63072000\n\
\n\
	default_backend backend0\n\
\n\
backend backend0\n\
	timeout connect 120s\n\
	timeout server 120s\n\
        option forwardfor except 127.0.0.0/8\n\
        http-request set-header X-Forwarded-Proto https\n\
        http-request set-header X-Forwarded-Port 8443\n\
	http-request set-header Host mysite.com\n\
        http-response set-header Content-Security-Policy upgrade-insecure-requests\n\
        server server0 127.0.0.1:8443 alpn h2,http/1.1 sni str(mysite.com) ssl verify none\n\
\n'>>/usr/local/etc/haproxy/haproxy.cfg

#USER haproxy

# https://github.com/docker-library/haproxy/issues/200
WORKDIR /var/lib/haproxy

CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
