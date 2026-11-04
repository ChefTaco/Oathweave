FROM node:24.22.1-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /build
RUN apt-get update -qq && apt-get install -y --no-install-recommends python3 make g++ ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . .
RUN npm ci --ignore-scripts && npm rebuild better-sqlite3 argon2 --ignore-scripts=false && npm --prefix tooling/release ci --ignore-scripts && npm run build && npm prune --omit=dev --ignore-scripts

FROM node:24.22.1-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
ENV NODE_ENV=production HIVE_AUTO_MIGRATE=false HIVE_AUTO_UPGRADE=false HIVE_UPDATE_CHECK=false HIVE_HOME=/data
RUN apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates util-linux openssl && rm -rf /var/lib/apt/lists/* && mkdir /data && chown node:node /data
WORKDIR /app
COPY --from=build --chown=node:node /build/package.json /app/package.json
COPY --from=build --chown=node:node /build/node_modules /app/node_modules
COPY --from=build --chown=node:node /build/apps/iam-core/dist /app/apps/iam-core/dist
COPY --from=build --chown=node:node /build/apps/iam-core/package.json /app/apps/iam-core/package.json
COPY --from=build --chown=node:node /build/apps/iam-core/prisma /app/apps/iam-core/prisma
COPY --from=build --chown=node:node /build/packages/iam-sdk/package.json /app/packages/iam-sdk/package.json
COPY LICENSE NOTICE /app/
COPY scripts/container-health.mjs /app/healthcheck.mjs
ENV HIVE_HEALTH_URL=https://localhost:4200/api/v1/health/ready
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 CMD ["node", "/app/healthcheck.mjs"]
USER node
WORKDIR /app/apps/iam-core
VOLUME ["/data"]
EXPOSE 4200
ENTRYPOINT ["node", "dist/cli.js"]
