import json

def check_base_image(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "FROM":
            base_image = step["value"][0]
            if "alpine:" in base_image:
                # Extract the version number from the base image
                version = base_image.split(":")[1]
                if version < "3.12":
                    return f"Using an outdated base image ({base_image}) is not allowed"
    return None

def check_root_password(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "RUN" and "echo \"root:insecurepassword\" | chpasswd" in step["value"][0]:
            return "Setting the root password to 'insecurepassword' is not recommended"
    return None

def check_sensitive_data(dockerfile_data):
    sensitive_data_flags = ["PASSWORD", "SECRET", "TOKEN", "KEY"]
    violations = []
    
    for step in dockerfile_data:
        if step["cmd"] == "ENV":
            env_var = step["value"][0]
            for flag in sensitive_data_flags:
                if flag in env_var:
                    if env_var.startswith(f"{flag}="):
                        # If the sensitive data is passed dynamically, give a warning
                        violations.append(f"WARNING: Detected dynamically passed sensitive data in ENV variable: {env_var}")
                    else:
                        # If the sensitive data is hardcoded, add it to the report
                        violations.append(f"Detected sensitive data in ENV variable: {env_var}")
    return violations

def check_latest_tag(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "FROM":
            base_image = step["value"][0]
            if ":latest" in base_image:
                return f"Avoid using the 'latest' tag for the base image ({base_image}). Use specific versions instead."
    return None

def check_non_root_user(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "RUN":
            if "adduser" in step["value"][0] and "USER" not in step["value"][0]:
                return "Running the 'adduser' command without switching to a non-root user afterwards. Please switch to a non-root user after creating it."
            if "useradd" in step["value"][0] and "USER" not in step["value"][0]:
                return "Running the 'useradd' command without switching to a non-root user afterwards. Please switch to a non-root user after creating it."
        if step["cmd"] == "USER" and "root" in step["value"][0]:
            return "Using 'root' as the container user is not recommended. Please use a non-root user instead."
    return None


def check_use_copy(dockerfile_data):
    for step in dockerfile_data:
        if step["cmd"] == "ADD":
            sources = step["value"][:-1]
            for source in sources:
                if source.startswith("http://") or source.startswith("https://"):
                    return "Avoid using ADD with remote URLs. Use COPY instead for local files."
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
        violations.extend(sensitive_data_violation)

    latest_tag_violation = check_latest_tag(dockerfile_data)
    if latest_tag_violation:
        violations.append(latest_tag_violation)

    non_root_user_violation = check_non_root_user(dockerfile_data)
    if non_root_user_violation:
        violations.append(non_root_user_violation)


    use_copy_violation = check_use_copy(dockerfile_data)
    if use_copy_violation:
        violations.append(use_copy_violation)

    # Display violations
    if violations:
        print("Policy Violations:")
        for violation in violations:
            print("-", violation)
    else:
        print("No policy violations found.")

if __name__ == "__main__":
    main()
