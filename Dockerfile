FROM golang:1.25-alpine AS builder                                                                                                                          

RUN apk add --no-cache clang llvm make libbpf-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

FROM alpine:3.19
RUN apk add --no-cache libbpf

COPY --from=builder /app/eghostbuster /usr/local/bin/

ENTRYPOINT ["eghostbuster"]
