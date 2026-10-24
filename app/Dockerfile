FROM node:24-alpine
WORKDIR /app
COPY server.mjs test.mjs ./
# Test de bout en bout (faux relais, faux Authentik) : une image rouge n'est jamais poussée.
RUN node test.mjs && rm test.mjs
# Durcissement runtime : plus d'installeur ni d'outil de téléchargement dans l'image finale.
RUN apk --purge del apk-tools; \
    rm -rf /sbin/apk /etc/apk /lib/apk /usr/share/apk /var/cache/apk \
      /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn* /usr/local/bin/pnpm* /opt/yarn* \
      /usr/bin/wget /usr/bin/curl /usr/bin/nc /usr/bin/telnet /usr/bin/ssl_client /usr/bin/ftpget /usr/bin/ftpput /usr/bin/tftp
USER node
EXPOSE 3000
CMD ["node", "server.mjs"]
