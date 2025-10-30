"""
Input and Configuration Validator
==================================

Validates user inputs, configuration files, and system requirements
before running the passive reconnaissance tool.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


class Validator:
    """Validates inputs and configuration for the passive recon tool."""

    # Regular expression for validating domain names
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'  # Subdomains
        r'+[a-zA-Z]{2,}$'  # TLD
    )

    # Regular expression for validating organization names
    ORG_NAME_REGEX = re.compile(r'^[a-zA-Z0-9\s\-\._&]+$')

    # Required configuration keys
    REQUIRED_CONFIG_KEYS = [
        'scope',
        'search_engines',
        'output'
    ]

    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a domain name.

        Args:
            domain: Domain name to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not domain:
            return False, "Domain cannot be empty"

        if len(domain) > 253:
            return False, "Domain name too long (max 253 characters)"

        if domain.startswith('-') or domain.endswith('-'):
            return False, "Domain cannot start or end with hyphen"

        if domain.startswith('.') or domain.endswith('.'):
            return False, "Domain cannot start or end with dot"

        if '..' in domain:
            return False, "Domain cannot contain consecutive dots"

        if not Validator.DOMAIN_REGEX.match(domain):
            return False, "Invalid domain name format"

        return True, None

    @staticmethod
    def validate_organization_name(name: str) -> Tuple[bool, Optional[str]]:
        """
        Validate an organization name.

        Args:
            name: Organization name to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not name:
            return False, "Organization name cannot be empty"

        if len(name) < 2:
            return False, "Organization name too short (min 2 characters)"

        if len(name) > 100:
            return False, "Organization name too long (max 100 characters)"

        if not Validator.ORG_NAME_REGEX.match(name):
            return False, "Organization name contains invalid characters"

        return True, None

    @staticmethod
    def validate_targets(targets: List[str]) -> Tuple[bool, List[str]]:
        """
        Validate a list of target domains and organization names.

        Args:
            targets: List of domains or organization names

        Returns:
            Tuple of (all_valid, error_messages)
        """
        if not targets:
            return False, ["No targets provided"]

        errors = []
        valid_count = 0

        for target in targets:
            target = target.strip()

            # Try as domain first
            domain_valid, domain_error = Validator.validate_domain(target)
            if domain_valid:
                valid_count += 1
                continue

            # Try as organization name
            org_valid, org_error = Validator.validate_organization_name(target)
            if org_valid:
                valid_count += 1
                continue

            # Both validations failed
            errors.append(f"Invalid target '{target}': not a valid domain or organization name")

        if valid_count == 0:
            errors.insert(0, "No valid targets found")

        return len(errors) == 0, errors

    @staticmethod
    def validate_config_file(config_path: Path) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Validate configuration file exists and is valid JSON.

        Args:
            config_path: Path to configuration file

        Returns:
            Tuple of (is_valid, error_message, config_dict)
        """
        if not config_path.exists():
            return False, f"Configuration file not found: {config_path}", None

        if not config_path.is_file():
            return False, f"Configuration path is not a file: {config_path}", None

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Validate required keys
            missing_keys = [
                key for key in Validator.REQUIRED_CONFIG_KEYS
                if key not in config
            ]

            if missing_keys:
                return False, f"Missing required keys in config: {', '.join(missing_keys)}", None

            return True, None, config

        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in configuration file: {e}", None
        except Exception as e:
            return False, f"Error reading configuration file: {e}", None

    @staticmethod
    def validate_config_values(config: Dict) -> Tuple[bool, List[str]]:
        """
        Validate configuration values are reasonable.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, warnings)
        """
        warnings = []

        # Check scope settings
        if 'scope' in config:
            max_subdomains = config['scope'].get('max_subdomains', 1000)
            if max_subdomains < 10:
                warnings.append("max_subdomains is very low, may miss results")
            if max_subdomains > 10000:
                warnings.append("max_subdomains is very high, may take a long time")

        # Check search engine settings
        if 'search_engines' in config:
            max_results = config['search_engines'].get('max_results_per_query', 50)
            if max_results < 10:
                warnings.append("max_results_per_query is very low")
            if max_results > 100:
                warnings.append("max_results_per_query is very high, may trigger rate limits")

            # Check browser settings if enabled
            if config['search_engines'].get('use_browser', False):
                browser_count = config['search_engines'].get('browser_count', 3)
                tabs_per_browser = config['search_engines'].get('tabs_per_browser', 12)

                if browser_count < 1:
                    warnings.append("browser_count must be at least 1")
                if browser_count > 5:
                    warnings.append("browser_count > 5 may consume excessive resources")

                if tabs_per_browser < 1:
                    warnings.append("tabs_per_browser must be at least 1")
                if tabs_per_browser > 20:
                    warnings.append("tabs_per_browser > 20 may cause stability issues")

        # Check output settings
        if 'output' in config:
            formats = config['output'].get('formats', [])
            if not formats:
                warnings.append("No output formats specified")

            valid_formats = ['json', 'csv', 'html', 'txt']
            invalid = [f for f in formats if f not in valid_formats]
            if invalid:
                warnings.append(f"Invalid output formats: {', '.join(invalid)}")

        # Check rate limits
        if 'rate_limits' in config:
            for service, limits in config['rate_limits'].items():
                rpm = limits.get('requests_per_minute', 0)
                if rpm > 100:
                    warnings.append(f"{service}: requests_per_minute > 100 may trigger bans")

        return True, warnings

    @staticmethod
    def validate_scope_file(scope_file_path: Optional[Path]) -> Tuple[bool, Optional[str], List[str]]:
        """
        Validate scope file if provided.

        Args:
            scope_file_path: Path to scope file (optional)

        Returns:
            Tuple of (is_valid, error_message, domains)
        """
        if scope_file_path is None:
            return True, None, []

        if not scope_file_path.exists():
            return False, f"Scope file not found: {scope_file_path}", []

        if not scope_file_path.is_file():
            return False, f"Scope file path is not a file: {scope_file_path}", []

        try:
            with open(scope_file_path, 'r') as f:
                lines = f.readlines()

            domains = []
            invalid_lines = []

            for i, line in enumerate(lines, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Validate as domain
                is_valid, error = Validator.validate_domain(line)
                if is_valid:
                    domains.append(line)
                else:
                    invalid_lines.append(f"Line {i}: {line} - {error}")

            if invalid_lines and len(domains) == 0:
                return False, f"No valid domains in scope file. Errors:\n" + "\n".join(invalid_lines), []

            if invalid_lines:
                # Has some valid domains but also invalid ones - return warning
                warning = f"Some invalid domains in scope file (skipped):\n" + "\n".join(invalid_lines[:5])
                if len(invalid_lines) > 5:
                    warning += f"\n... and {len(invalid_lines) - 5} more"
                return True, warning, domains

            return True, None, domains

        except Exception as e:
            return False, f"Error reading scope file: {e}", []

    @staticmethod
    def validate_output_directory(output_dir: Path) -> Tuple[bool, Optional[str]]:
        """
        Validate output directory exists or can be created.

        Args:
            output_dir: Path to output directory

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            # Check if writable
            test_file = output_dir / '.write_test'
            try:
                test_file.touch()
                test_file.unlink()
                return True, None
            except Exception as e:
                return False, f"Output directory is not writable: {e}"

        except Exception as e:
            return False, f"Cannot create output directory: {e}"

    @staticmethod
    def validate_all(
        targets: List[str],
        config_path: Path,
        scope_file_path: Optional[Path] = None
    ) -> Tuple[bool, Dict]:
        """
        Perform comprehensive validation of all inputs.

        Args:
            targets: List of target domains/organizations
            config_path: Path to configuration file
            scope_file_path: Optional path to scope file

        Returns:
            Tuple of (is_valid, results_dict)
            results_dict contains: errors, warnings, config
        """
        results = {
            'errors': [],
            'warnings': [],
            'config': None
        }

        # Validate targets
        targets_valid, target_errors = Validator.validate_targets(targets)
        if not targets_valid:
            results['errors'].extend(target_errors)

        # Validate configuration file
        config_valid, config_error, config = Validator.validate_config_file(config_path)
        if not config_valid:
            results['errors'].append(config_error)
        else:
            results['config'] = config

            # Validate configuration values
            _, config_warnings = Validator.validate_config_values(config)
            results['warnings'].extend(config_warnings)

            # Validate output directory
            output_dir = Path(config.get('output', {}).get('directory', 'results'))
            output_valid, output_error = Validator.validate_output_directory(output_dir)
            if not output_valid:
                results['errors'].append(output_error)

        # Validate scope file if provided
        if scope_file_path:
            scope_valid, scope_message, _ = Validator.validate_scope_file(scope_file_path)
            if not scope_valid:
                results['errors'].append(scope_message)
            elif scope_message:  # Warning
                results['warnings'].append(scope_message)

        is_valid = len(results['errors']) == 0

        return is_valid, results
