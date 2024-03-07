# Stage 1: compiling the application
FROM golang:1.21.0-alpine AS builder

# set the working directory
WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# add the rest of the source code
COPY . .

# Navigate to the directory containing the main.go file
WORKDIR /app/cmd/dnssecanalyser

# Build the application with optimization flags
RUN go build -ldflags="-w -s" -o app ./main.go

# Stage 2: running the application
FROM alpine:3.19

# Install bind-tools (delv)
RUN apk add --no-cache bind-tools

# Add a non-root user
RUN adduser -D dnssecanalyser
USER dnssecanalyser

# Copy the compiled application from the builder stage
COPY --from=builder /app/cmd/dnssecanalyser/app /dnssecanalyser/app
COPY --from=builder /app/config.yaml /dnssecanalyser/config.yaml

WORKDIR /dnssecanalyser/
# Run the compiled binary
CMD ["/dnssecanalyser/app"]
