FROM node:24-trixie-slim AS build
WORKDIR /app
COPY server.mjs test.mjs ./
# Test de bout en bout (faux relais, faux Authentik) : une image rouge n'est jamais poussée.
RUN node test.mjs

# Image finale distroless (Debian 13, sans shell ni gestionnaire de paquets), épinglée par digest.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8
WORKDIR /app
COPY --from=build --chown=65532:65532 /app/server.mjs ./server.mjs
USER 65532:65532
EXPOSE 3000
CMD ["server.mjs"]
