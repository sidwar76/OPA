import json

def check_base_image(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "FROM" and step["value"][0] == "alpine:3.11":
            return "Using an outdated base image (alpine:3.11) is not allowed"
    return None

def check_root_password(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "RUN" and "echo \"root:insecurepassword\" | chpasswd" in step["value"][0]:
            return "Setting the root password to 'insecurepassword' is not recommended"
    return None

def check_sensitive_data(dockerfile_data):
    sensitive_data_flags = ["PASSWORD", "SECRET", "TOKEN", "KEY"]
    for step in dockerfile_data:
        if step["cmd"] == "ENV":
            for flag in sensitive_data_flags:
                if flag in step["value"][0]:
                    return f"Detected sensitive data in ENV variable: {step['value'][0]}"
    return None

def main():
    with open("Dockerfile.json", "r") as f:
        dockerfile_data = json.load(f)

    violations = []

    # Apply the rules
    base_image_violation = check_base_image(dockerfile_data)
    if base_image_violation:
        violations.append(base_image_violation)

    root_password_violation = check_root_password(dockerfile_data)
    if root_password_violation:
        violations.append(root_password_violation)

    sensitive_data_violation = check_sensitive_data(dockerfile_data)
    if sensitive_data_violation:
        violations.append(sensitive_data_violation)

    # Display violations
    if violations:
        print("Policy Violations:")
        for violation in violations:
            print("-", violation)
    else:
        print("No policy violations found.")

if __name__ == "__main__":
    main()
