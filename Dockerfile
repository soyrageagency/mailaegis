# MailAegis — Corporate Email Threat Analyzer
# Crafted by SoyRage Agency — https://soyrage.es/
#
# Two stages, because the analyzer has zero runtime dependencies: TypeScript
# and the build tooling exist only in the first, and the image that actually
# ships is Node plus `dist/`.

# ---- build ------------------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

# Dependencies first, so a source change does not re-resolve the tree.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build

# ---- runtime ----------------------------------------------------------------
FROM node:20-alpine AS runtime

LABEL org.opencontainers.image.title="MailAegis" \
      org.opencontainers.image.description="Corporate email threat analyzer: phishing, malware and BEC detection with VirusTotal, ClamAV, SPF/DKIM/DMARC and delivery-path forensics." \
      org.opencontainers.image.vendor="SoyRage Agency" \
      org.opencontainers.image.url="https://soyrage.es/" \
      org.opencontainers.image.source="https://github.com/soyrageagency/mailaegis" \
      org.opencontainers.image.licenses="SEE LICENSE IN LICENSE"

WORKDIR /app

# Only the compiled output and the licence travel. No node_modules: there are
# no runtime dependencies to install.
COPY --from=build /app/dist ./dist
COPY package.json LICENSE NOTICE ./

# Reports, the audit trail, sender lists and labels all live here. Declared as
# a volume so a container restart does not lose the audit trail.
RUN mkdir -p /data && chown -R node:node /data
VOLUME ["/data"]
ENV MAILAEGIS_OUT_DIR=/data

# 127.0.0.1 is the right default for a laptop and useless in a container —
# nothing outside the network namespace could reach it. Binding wide makes
# MAILAEGIS_API_TOKEN important; the compose file and the README both say so.
ENV MAILAEGIS_HOST=0.0.0.0 \
    MAILAEGIS_PORT=4850 \
    NODE_ENV=production

# Runs unprivileged. The image needs to write nowhere except /data.
USER node
EXPOSE 4850

# Busybox wget is already in the base image, so no extra package is pulled in
# just to answer "is it up?".
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${MAILAEGIS_PORT}/api/meta" || exit 1

ENTRYPOINT ["node", "dist/index.js"]
CMD ["serve"]
