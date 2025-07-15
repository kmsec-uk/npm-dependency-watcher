FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY main.go go.mod go.sum ./
RUN go build -v -o /app/dep-watcher

FROM alpine:3.18
COPY --from=builder /app/dep-watcher /app/dep-watcher
RUN addgroup -g 101 -S dep-watcher && adduser -h /app -u 1001 -D dep-watcher -G dep-watcher
USER dep-watcher
CMD ["/app/dep-watcher"]