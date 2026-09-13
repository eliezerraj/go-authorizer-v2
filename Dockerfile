# docker build -t go-authorizer-v2 .
# docker run -dit --name go-authorizer-v2 -p 7100:7100 go-authorizer-v2

FROM golang:1.25 AS builder

RUN apt-get update && apt-get install bash && apt-get install -y --no-install-recommends ca-certificates

WORKDIR /app
COPY . .
RUN go mod tidy

WORKDIR /app/cmd
RUN go build -o go-authorizer-v2 -ldflags '-linkmode external -w -extldflags "-static"'

FROM alpine

WORKDIR /app
COPY --from=builder /app/cmd/go-authorizer-v2 .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

CMD ["/app/go-authorizer-v2"]