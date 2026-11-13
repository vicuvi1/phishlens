# CLI image:  docker run --rm -v "$PWD:/mail:ro" phishlens /mail/suspicious.eml
FROM node:22-alpine
WORKDIR /app
COPY package.json cli.js ./
COPY src ./src
USER node
ENTRYPOINT ["node", "/app/cli.js"]
