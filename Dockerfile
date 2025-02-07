FROM golang:1.23-bookworm AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

WORKDIR /build/cmd

RUN go build -o ../app

FROM gcr.io/distroless/base-debian12

WORKDIR /

COPY --from=builder /build/app /app

EXPOSE 8080

CMD ["/app"]