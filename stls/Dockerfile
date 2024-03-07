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
WORKDIR /app/cmd/stls

# Build the application with optimization flags
RUN go build -ldflags="-w -s" -o app ./main.go



# Stage 2: running the application
FROM alpine:3.19

# Add a non-root user
RUN adduser -D stls

# Install OpenSSL and bash for testssl.sh, and any other dependencies
RUN apk add --no-cache bash openssl coreutils procps

# Download testssl.sh
WORKDIR /home/stls
RUN wget https://github.com/drwetter/testssl.sh/archive/refs/heads/3.0.zip && \
    unzip 3.0.zip && \
    mv testssl.sh-3.0 testssl.sh && \
    rm 3.0.zip && \
    chmod +x testssl.sh/testssl.sh && \
    mkdir "results" && \
    chmod 700 "results"


# Copy the compiled application from the builder stage
COPY --from=builder /app/cmd/stls/app /home/stls/app

# Change ownership to the non-root user
RUN chown -R stls:stls /home/stls

USER stls

# Set the volume where the results will be stored
VOLUME ["/home/stls/results"]

# Run the compiled binary
CMD ["/home/stls/app"]