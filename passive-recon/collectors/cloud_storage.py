"""
Cloud Storage Collector
========================

Discovers and enumerates public cloud storage buckets:
- AWS S3 buckets
- Azure Blob Storage
- Google Cloud Storage (GCS)
- DigitalOcean Spaces
- Backblaze B2

Techniques:
- Name permutation and brute force
- DNS resolution
- Certificate analysis
- Discovered URLs scraping
"""

import logging
from typing import Dict, List, Set


logger = logging.getLogger(__name__)


class CloudStorageCollector:
    """
    Discovers public cloud storage buckets and containers.
    Tests for common naming patterns and misconfigurations.
    """

    # Common S3 bucket name patterns
    BUCKET_PATTERNS = [
        '{brand}',
        '{brand}-{suffix}',
        '{brand}.{suffix}',
        '{brand}_{suffix}',
        '{domain}',
        '{domain}-{suffix}',
    ]

    # Common suffixes
    SUFFIXES = [
        'backup', 'backups', 'bak', 'archive', 'archives',
        'prod', 'production', 'stage', 'staging', 'dev', 'development',
        'test', 'testing', 'qa',
        'assets', 'static', 'media', 'files', 'uploads', 'images',
        'data', 'database', 'db', 'logs',
        'public', 'private', 'secret', 'confidential',
        'www', 'web', 'site', 'website',
        'cdn', 'content',
        'app', 'application', 'api'
    ]

    def __init__(self, config: Dict, cache_manager):
        """
        Initialize cloud storage collector.

        Args:
            config: Configuration dictionary
            cache_manager: CacheManager instance
        """
        self.config = config
        self.cache_manager = cache_manager

    def collect(self, scope: Dict) -> List[Dict]:
        """
        Discover cloud storage buckets.

        Args:
            scope: Scope dictionary

        Returns:
            List of discovered buckets/containers
        """
        findings = []

        # Generate candidate bucket names
        candidates = self._generate_bucket_names(scope)
        logger.info(f"Testing {len(candidates)} potential bucket names...")

        # Test S3 buckets
        findings.extend(self._test_s3_buckets(candidates))

        # Test GCS buckets
        findings.extend(self._test_gcs_buckets(candidates))

        # Test Azure containers
        findings.extend(self._test_azure_containers(scope))

        logger.info(f"Cloud Storage: Found {len(findings)} accessible buckets")
        return findings

    def _generate_bucket_names(self, scope: Dict) -> Set[str]:
        """
        Generate potential bucket names from scope.

        Args:
            scope: Scope dictionary

        Returns:
            Set of candidate bucket names
        """
        candidates = set()

        # Get brands and domains
        brands = scope.get('brands', [])
        domains = scope.get('root_domains', [])

        # Generate from brands
        for brand in brands:
            clean_brand = brand.lower().replace(' ', '').replace('-', '')
            candidates.add(clean_brand)

            for suffix in self.SUFFIXES:
                candidates.add(f"{clean_brand}-{suffix}")
                candidates.add(f"{clean_brand}{suffix}")
                candidates.add(f"{suffix}-{clean_brand}")

        # Generate from domains
        for domain in domains:
            base = domain.split('.')[0]
            candidates.add(base)
            candidates.add(domain.replace('.', '-'))

            for suffix in self.SUFFIXES:
                candidates.add(f"{base}-{suffix}")

        return candidates

    def _test_s3_buckets(self, bucket_names: Set[str]) -> List[Dict]:
        """
        Test if S3 buckets exist and are accessible.

        Args:
            bucket_names: Set of bucket names to test

        Returns:
            List of accessible buckets
        """
        findings = []

        try:
            import requests

            for bucket_name in bucket_names:
                cache_key = f"s3:{bucket_name}"
                cached = self.cache_manager.get(cache_key)

                if cached is not None:
                    if cached:  # If cache has a result
                        findings.append(cached)
                    continue

                # Test bucket existence
                url = f"https://{bucket_name}.s3.amazonaws.com/"

                try:
                    response = requests.head(url, timeout=5, allow_redirects=False)

                    # Various status codes indicate different states
                    if response.status_code == 200:
                        # Bucket exists and is publicly accessible
                        finding = {
                            'type': 's3_bucket',
                            'bucket_name': bucket_name,
                            'url': url,
                            'status': 'public_readable',
                            'category': 'cloud_storage',
                            'source': 'aws_s3',
                            'severity': 'high',
                            'description': 'Publicly accessible S3 bucket'
                        }
                        findings.append(finding)
                        self.cache_manager.set(cache_key, finding, ttl=7200)

                    elif response.status_code == 403:
                        # Bucket exists but access denied (still a finding)
                        finding = {
                            'type': 's3_bucket',
                            'bucket_name': bucket_name,
                            'url': url,
                            'status': 'exists_private',
                            'category': 'cloud_storage',
                            'source': 'aws_s3',
                            'severity': 'low',
                            'description': 'S3 bucket exists (private)'
                        }
                        findings.append(finding)
                        self.cache_manager.set(cache_key, finding, ttl=7200)

                    else:
                        # Cache negative result
                        self.cache_manager.set(cache_key, None, ttl=86400)

                except requests.RequestException:
                    # Bucket doesn't exist or network error
                    self.cache_manager.set(cache_key, None, ttl=86400)

        except ImportError:
            logger.warning("requests library not installed")

        return findings

    def _test_gcs_buckets(self, bucket_names: Set[str]) -> List[Dict]:
        """
        Test if Google Cloud Storage buckets exist.

        Args:
            bucket_names: Set of bucket names to test

        Returns:
            List of accessible buckets
        """
        findings = []

        try:
            import requests

            for bucket_name in bucket_names:
                cache_key = f"gcs:{bucket_name}"
                cached = self.cache_manager.get(cache_key)

                if cached is not None:
                    if cached:
                        findings.append(cached)
                    continue

                # GCS bucket URL
                url = f"https://storage.googleapis.com/{bucket_name}/"

                try:
                    response = requests.head(url, timeout=5, allow_redirects=False)

                    if response.status_code == 200:
                        finding = {
                            'type': 'gcs_bucket',
                            'bucket_name': bucket_name,
                            'url': url,
                            'status': 'public_readable',
                            'category': 'cloud_storage',
                            'source': 'google_gcs',
                            'severity': 'high',
                            'description': 'Publicly accessible GCS bucket'
                        }
                        findings.append(finding)
                        self.cache_manager.set(cache_key, finding, ttl=7200)

                    elif response.status_code in [403, 401]:
                        finding = {
                            'type': 'gcs_bucket',
                            'bucket_name': bucket_name,
                            'url': url,
                            'status': 'exists_private',
                            'category': 'cloud_storage',
                            'source': 'google_gcs',
                            'severity': 'low',
                            'description': 'GCS bucket exists (private)'
                        }
                        findings.append(finding)
                        self.cache_manager.set(cache_key, finding, ttl=7200)

                    else:
                        self.cache_manager.set(cache_key, None, ttl=86400)

                except requests.RequestException:
                    self.cache_manager.set(cache_key, None, ttl=86400)

        except ImportError:
            logger.warning("requests library not installed")

        return findings

    def _test_azure_containers(self, scope: Dict) -> List[Dict]:
        """
        Test for Azure Blob Storage containers.

        Azure blob URLs: https://{account}.blob.core.windows.net/{container}

        Args:
            scope: Scope dictionary

        Returns:
            List of accessible containers
        """
        findings = []

        # Azure requires account name, harder to enumerate without hints
        # Would need to discover account names first through other means

        return findings

    def check_bucket_permissions(self, bucket_url: str, bucket_type: str = 's3') -> Dict:
        """
        Perform detailed permission check on a bucket.

        Tests for:
        - List objects
        - Read objects
        - Write objects (dangerous!)
        - ACL read/write

        WARNING: This performs active checks. Only use with explicit authorization.

        Args:
            bucket_url: Full URL to bucket
            bucket_type: Type of bucket (s3, gcs, azure)

        Returns:
            Dictionary of permission test results
        """
        # Placeholder - implement with caution
        # This would require active testing which may be out of passive scope
        return {
            'list': False,
            'read': False,
            'write': False,
            'note': 'Active permission testing not implemented'
        }
