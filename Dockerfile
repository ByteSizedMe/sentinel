# Two stages: build static binaries with the Go toolchain, then copy just those
# (and the SQL migrations) into a minimal image with no shell and no package
# manager. Both base images are pinned by tag and digest.
#
# No secrets are baked in: every setting (DATABASE_URL, JWT_SECRET, ...) is
# passed at run time with -e or --env-file. See the README, "Container".

# The tag matches the "go" line in go.mod.
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
WORKDIR /src

# Dependencies first, so this layer is reused until go.mod or go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Only what the two binaries need. cmd/tokengen (the dev token minter) is
# deliberately not copied, so it can never end up in the image.
COPY cmd/sentinel ./cmd/sentinel
COPY cmd/migrate ./cmd/migrate
COPY internal ./internal

# CGO off gives a fully static binary that runs on the "static" base image.
# -trimpath removes build paths; -s -w drop the symbol and debug tables.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/sentinel ./cmd/sentinel \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/migrate ./cmd/migrate

# distroless "static" with the "nonroot" user: no shell, no package manager, no
# libc. Debian 12 based.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /app
COPY --from=build /out/sentinel /out/migrate ./
COPY migrations ./migrations

# cmd/migrate reads the SQL files from this folder.
ENV MIGRATIONS_DIR=/app/migrations

# 65532 is the "nonroot" user of the base image. A number (not a name) lets
# orchestrators verify the user is not root.
USER 65532:65532

EXPOSE 8080

# The server. To run migrations instead, override the entrypoint:
#   docker run --rm --entrypoint /app/migrate -e MIGRATE_DATABASE_URL=... sentinel up
# There is no HEALTHCHECK: the image has no shell or curl. Point the load
# balancer's health check at GET /health.
ENTRYPOINT ["/app/sentinel"]
