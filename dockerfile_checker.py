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

def check_unused_dependencies(dockerfile_data):
    # List of packages to ignore from being considered as unused
    ignored_packages = ["curl", "wget"]  # Add more if needed

    # List of packages that are installed and used in the Dockerfile
    used_packages = set()

    # Find the installed packages
    for step in dockerfile_data:
        if step["cmd"] == "RUN" and "apk add" in step["value"][0]:
            packages = step["value"][0].replace("apk add", "").strip()
            used_packages.update(packages.split())

    # Find the packages declared to be removed (if any)
    for step in dockerfile_data:
        if step["cmd"] == "RUN" and "apk del" in step["value"][0]:
            removed_packages = step["value"][0].replace("apk del", "").strip()
            removed_packages = set(removed_packages.split())
            used_packages.difference_update(removed_packages)

    # Check for unused packages
    unused_packages = used_packages.difference(ignored_packages)
    if unused_packages:
        return f"Unused dependencies found in the Dockerfile: {', '.join(unused_packages)}"
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

    unused_dependencies_violation = check_unused_dependencies(dockerfile_data)
    if unused_dependencies_violation:
        violations.append(unused_dependencies_violation)

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
