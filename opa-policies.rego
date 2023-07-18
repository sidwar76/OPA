package docker.security

# Disallow the use of outdated and vulnerable base images
deny[msg] {
    input.from.image.tag == "3.11"
    msg = "Using an outdated base image (alpine:3.11) is not allowed"
}

# Disallow setting passwords in Dockerfile
deny[msg] {
    contains(input.run.instructions[_], "echo \"root:insecurepassword\" | chpasswd")
    msg = "Setting passwords in Dockerfile is not allowed"
}

# Disallow installing packages as root
deny[msg] {
    contains(input.run.instructions[_], "apk add")
    contains(input.run.instructions[_], "--no-cache")
    contains(input.run.instructions[_], "curl")
    msg = "Installing packages as root is not allowed"
}

# Disallow unnecessary port exposure
deny[msg] {
    contains(input.expose.ports, 80)
    msg = "Exposing port 80 is unnecessary"
}

# Disallow setting sensitive information as environment variables
deny[msg] {
    input.env.vars[_].key == "API_KEY"  # Example: Detecting API_KEY
    msg = "Setting sensitive information (API_KEY) as environment variables is not allowed"
}

deny[msg] {
    input.env.vars[_].key == "PASSWORD"  # Example: Detecting PASSWORD
    msg = "Setting sensitive information (PASSWORD) as environment variables is not allowed"
}
