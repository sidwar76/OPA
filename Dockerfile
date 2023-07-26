# Use an outdated and vulnerable base image
FROM alpine:3.11

# Set a default password (avoid doing this in real projects)
RUN echo "root:insecurepassword" | chpasswd

# Install packages as root (should use a non-root user for security)
RUN apk add --no-cache curl jq  # jq is the unused package

# Expose an unnecessary port (not required for this example)
EXPOSE 80

# Set environment variables with sensitive information
ENV API_KEY=your_api_key
ENV PASSWORD=your_password

# Add a file from a remote URL (will trigger the ADD issue)
ADD https://github.com/moby/moby/blob/master/internal/mod/mod.go /app/

# Use COPY instead of ADD for local file
COPY gitleaks.toml /app/

# Unnecessary command to install 'tree'
RUN apk add --no-cache tree && \
    apk del --no-cache tree  # Uninstalling immediately, but still an unused package
