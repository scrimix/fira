FROM node:22-bookworm-slim

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

WORKDIR /app

COPY package.json pnpm-lock.yaml* ./
# --reporter=append-only forces line-per-event output so docker build logs
# show real progress instead of a hidden spinner.
RUN pnpm install --reporter=append-only

EXPOSE 5173
CMD ["pnpm", "dev", "--host", "0.0.0.0"]
