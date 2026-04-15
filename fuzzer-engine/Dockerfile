# Сборка
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /sentinel-go main.go

# Запуск
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
# Копирует бинарник в системную папку
COPY --from=builder /sentinel-go /usr/local/bin/sentinel-go
RUN chmod +x /usr/local/bin/sentinel-go

# Указывает прямой путь к исполняемому файлу
ENTRYPOINT ["/usr/local/bin/sentinel-go"]



