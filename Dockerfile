# syntax=docker/dockerfile:1
# rypt-store: Node build of web/, Go build with the SPA embedded, distroless
# runtime as a non-root user (core 13).

FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY api/openapi.yaml /src/api/openapi.yaml
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X github.com/x6c-co/rypt-store/internal/version.Version=${VERSION}" \
      -o /out/rypt-store ./cmd/rypt-store \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rypt-store /usr/local/bin/rypt-store
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV RYPT_STORE_DATA_DIR=/data
VOLUME /data
EXPOSE 8443 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rypt-store"]
CMD ["server"]
