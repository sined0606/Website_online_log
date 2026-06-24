# Build stage — keine nativen Module nötig, aber apk bleibt für npm ci Kompatibilität
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Runtime stage — node:sqlite ist ab Node 22.5.0 verfügbar (Flag ab Node 23 nicht mehr nötig)
FROM node:22-alpine
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY . .

RUN mkdir -p data

EXPOSE 3000

ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:3000/admin/session || exit 1

CMD ["node", "--experimental-sqlite", "server.js"]
