# The crash-test room. Every scenario runs in here, never on the host.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl sqlite3 python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} && npm cache clean --force

# Agents refuse "skip permissions" mode as root, and a non-root user is safer anyway.
RUN useradd -m -s /bin/bash dev
COPY harness /opt/crumple
USER dev
WORKDIR /home/dev
ENTRYPOINT ["node", "/opt/crumple/run.mjs"]
