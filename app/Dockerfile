FROM node:24-alpine
WORKDIR /app
COPY server.mjs test.mjs ./
# Test de bout en bout (faux relais, faux Authentik) : une image rouge n'est jamais poussée.
RUN node test.mjs && rm test.mjs
USER node
EXPOSE 3000
CMD ["node", "server.mjs"]
