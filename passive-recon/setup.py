#!/usr/bin/env python3
"""
Setup and Installation Script for Passive Reconnaissance Tool
==============================================================

This script:
- Checks Python version compatibility
- Validates and installs dependencies
- Sets up Playwright browsers (if requested)
- Creates necessary directories
- Validates configuration files
- Performs health checks

Usage:
    python3 setup.py [--skip-playwright] [--check-only]
"""

import sys
import subprocess
import os
import json
from pathlib import Path
from typing import Tuple, List, Optional

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(message: str):
    """Print a styled header message."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{message:^70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}\n")


def print_success(message: str):
    """Print a success message."""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_error(message: str):
    """Print an error message."""
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")


def print_warning(message: str):
    """Print a warning message."""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")


def print_info(message: str):
    """Print an info message."""
    print(f"{Colors.OKCYAN}ℹ {message}{Colors.ENDC}")


def check_python_version() -> Tuple[bool, str]:
    """Check if Python version meets requirements."""
    required_major = 3
    required_minor = 8

    current_version = sys.version_info
    meets_requirement = (
        current_version.major == required_major and
        current_version.minor >= required_minor
    )

    version_str = f"{current_version.major}.{current_version.minor}.{current_version.micro}"

    return meets_requirement, version_str


def check_pip_available() -> bool:
    """Check if pip is available."""
    try:
        subprocess.run(
            ["pip3", "--version"],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_dependencies(skip_playwright: bool = False) -> bool:
    """Install required dependencies from requirements.txt."""
    requirements_file = Path("requirements.txt")

    if not requirements_file.exists():
        print_error(f"requirements.txt not found at {requirements_file}")
        return False

    print_info("Installing Python dependencies...")

    try:
        # Install dependencies
        subprocess.run(
            ["pip3", "install", "-r", str(requirements_file)],
            check=True
        )
        print_success("Python dependencies installed successfully")

        # Install Playwright browsers if not skipped
        if not skip_playwright:
            print_info("Installing Playwright browsers (this may take a few minutes)...")
            try:
                subprocess.run(
                    ["playwright", "install", "chromium"],
                    check=True
                )
                print_success("Playwright browsers installed successfully")
            except subprocess.CalledProcessError:
                print_warning("Playwright browser installation failed (optional feature)")
                print_info("You can install it later with: playwright install chromium")
        else:
            print_info("Skipping Playwright browser installation (use --skip-playwright)")

        return True

    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        return False


def check_dependencies() -> Tuple[bool, List[str]]:
    """Check if required dependencies are installed."""
    required_packages = [
        ("requests", "requests"),
        ("playwright", "playwright")
    ]

    missing_packages = []

    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package_name)

    return len(missing_packages) == 0, missing_packages


def create_directories() -> bool:
    """Create necessary directories for the tool."""
    directories = [
        "cache",
        "results",
        "logs"
    ]

    try:
        for directory in directories:
            dir_path = Path(directory)
            dir_path.mkdir(exist_ok=True)
            print_success(f"Directory '{directory}' ready")

        return True

    except Exception as e:
        print_error(f"Failed to create directories: {e}")
        return False


def validate_config_file() -> bool:
    """Validate the example configuration file."""
    config_example = Path("config.example.json")

    if not config_example.exists():
        print_error("config.example.json not found")
        return False

    try:
        with open(config_example, 'r') as f:
            config = json.load(f)

        print_success("config.example.json is valid JSON")

        # Check if config.json exists
        config_file = Path("config.json")
        if not config_file.exists():
            print_info("config.json not found - you should create one from config.example.json")
            print_info("  cp config.example.json config.json")
        else:
            print_success("config.json exists")

        return True

    except json.JSONDecodeError as e:
        print_error(f"config.example.json is invalid JSON: {e}")
        return False
    except Exception as e:
        print_error(f"Error reading config file: {e}")
        return False


def check_rules_files() -> bool:
    """Check if required rules files exist."""
    rules_files = [
        "rules/google_dorks.json",
        "rules/secret_patterns.json"
    ]

    all_exist = True

    for rules_file in rules_files:
        file_path = Path(rules_file)
        if file_path.exists():
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if 'google_dorks' in rules_file:
                        dork_count = sum(
                            len(cat.get('dorks', []))
                            for cat in data.get('categories', {}).values()
                        )
                        print_success(f"{rules_file} ({dork_count} dorks)")
                    elif 'secret_patterns' in rules_file:
                        pattern_count = len(data.get('patterns', {}))
                        print_success(f"{rules_file} ({pattern_count} patterns)")
            except Exception as e:
                print_error(f"{rules_file}: {e}")
                all_exist = False
        else:
            print_error(f"{rules_file} not found")
            all_exist = False

    return all_exist


def test_imports() -> Tuple[bool, List[str]]:
    """Test if all modules can be imported."""
    modules = [
        ("seeds.scope_builder", "ScopeBuilder"),
        ("collectors.search_engine", "SearchEngineCollector"),
        ("collectors.certificate_transparency", "CTCollector"),
        ("collectors.github_collector", "GitHubCollector"),
        ("collectors.cloud_storage", "CloudStorageCollector"),
        ("collectors.paste_sites", "PasteSiteCollector"),
        ("detectors.secret_detector", "SecretDetector"),
        ("detectors.vulnerability_detector", "VulnerabilityDetector"),
        ("detectors.admin_panel_detector", "AdminPanelDetector"),
        ("normalizers.url_normalizer", "URLNormalizer"),
        ("scorers.risk_scorer", "RiskScorer"),
        ("outputs.output_handler", "OutputHandler"),
        ("utils.cache_manager", "CacheManager"),
        ("utils.rate_limiter", "RateLimiter"),
    ]

    failed_imports = []

    for module_path, class_name in modules:
        try:
            module = __import__(module_path, fromlist=[class_name])
            getattr(module, class_name)
        except Exception as e:
            failed_imports.append(f"{module_path}.{class_name}: {str(e)}")

    return len(failed_imports) == 0, failed_imports


def run_health_check() -> bool:
    """Run a comprehensive health check."""
    print_info("Running health checks...")

    all_checks_passed = True

    # Check Python version
    python_ok, python_version = check_python_version()
    if python_ok:
        print_success(f"Python version {python_version} (>= 3.8 required)")
    else:
        print_error(f"Python version {python_version} (3.8+ required)")
        all_checks_passed = False

    # Check pip
    if check_pip_available():
        print_success("pip3 is available")
    else:
        print_error("pip3 is not available")
        all_checks_passed = False

    # Check dependencies
    deps_ok, missing = check_dependencies()
    if deps_ok:
        print_success("All required dependencies are installed")
    else:
        print_warning(f"Missing dependencies: {', '.join(missing)}")
        # Not a critical failure - can be installed

    # Check directories
    if create_directories():
        print_success("All required directories exist")
    else:
        all_checks_passed = False

    # Validate config
    if validate_config_file():
        print_success("Configuration files are valid")
    else:
        all_checks_passed = False

    # Check rules files
    if check_rules_files():
        print_success("All rules files are valid")
    else:
        all_checks_passed = False

    # Test imports
    imports_ok, failed = test_imports()
    if imports_ok:
        print_success("All modules can be imported successfully")
    else:
        print_error("Some modules failed to import:")
        for failure in failed:
            print(f"  - {failure}")
        all_checks_passed = False

    return all_checks_passed


def main():
    """Main setup function."""
    print_header("Passive Reconnaissance Tool - Setup")

    # Parse command line arguments
    skip_playwright = "--skip-playwright" in sys.argv
    check_only = "--check-only" in sys.argv

    if check_only:
        print_info("Running in check-only mode (no installation)")
        success = run_health_check()

        if success:
            print_header("✓ Health Check Passed")
            print_success("All systems ready!")
            print_info("Run: python3 passive_recon.py -c config.json -t <target>")
        else:
            print_header("✗ Health Check Failed")
            print_error("Some checks failed - please review the errors above")
            sys.exit(1)
    else:
        # Full setup
        print_info("Starting full setup...")

        # Check Python version
        python_ok, python_version = check_python_version()
        if not python_ok:
            print_error(f"Python {python_version} is not supported (3.8+ required)")
            sys.exit(1)
        print_success(f"Python {python_version} is compatible")

        # Check pip
        if not check_pip_available():
            print_error("pip3 is not available - please install pip first")
            sys.exit(1)
        print_success("pip3 is available")

        # Install dependencies
        if not install_dependencies(skip_playwright):
            print_error("Dependency installation failed")
            sys.exit(1)

        # Create directories
        if not create_directories():
            print_error("Failed to create required directories")
            sys.exit(1)

        # Validate configuration
        validate_config_file()

        # Run final health check
        print_header("Running Final Health Check")
        if run_health_check():
            print_header("✓ Setup Complete!")
            print_success("Passive Reconnaissance Tool is ready to use")
            print()
            print_info("Next steps:")
            print("  1. Copy config.example.json to config.json")
            print("  2. Edit config.json with your API keys (optional)")
            print("  3. Run: python3 passive_recon.py -c config.json -t example.com")
            print()
            print_info("For help: python3 passive_recon.py --help")
        else:
            print_warning("Setup completed with some warnings")
            print_info("Check the messages above for any issues")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_warning("Setup interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
