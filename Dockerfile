# Sample Dockerfile with security issues

# Use an outdated and vulnerable base image
FROM alpine:3.11

# Set a default password (avoid doing this in real projects)
RUN echo "root:insecurepassword" | chpasswd

# Install packages as root (should use a non-root user for security)
RUN apk add --no-cache curl

# Expose an unnecessary port (not required for this example)
EXPOSE 80

# Set environment variables with sensitive information
ENV API_KEY=your_api_key
ENV PASSWORD=your-password
