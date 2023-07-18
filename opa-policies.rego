package docker.security

# Disallow the use of outdated and vulnerable base images
deny[msg] {
    input[_].cmd == "FROM"
    input[_].value[0] == "alpine:3.11"
    msg = "Using an outdated base image (alpine:3.11) is not allowed"
}
