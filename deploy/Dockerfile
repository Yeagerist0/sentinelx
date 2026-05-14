# Backend image. Build context is the repo root:
#   docker build -f deploy/Dockerfile -t sentinelx .
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/sentinelx ./cmd/sentinelx

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/sentinelx /sentinelx
COPY rules /rules
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/sentinelx", "serve", "--addr", ":8080", "--rules", "/rules"]
