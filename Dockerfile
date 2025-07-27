# Build stage
FROM golang:1.24-alpine AS build
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-X main.version=$VERSION" -o /bin/finch ./cmd/finch

# Final image
FROM alpine:3.22
WORKDIR /app
COPY --from=build /bin/finch /usr/local/bin/finch
EXPOSE 8443
ENTRYPOINT ["finch"]
CMD ["--help"]
