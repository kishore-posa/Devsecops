FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /api-server main.go

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /api-server /api-server


EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT [ "/api-server" ]