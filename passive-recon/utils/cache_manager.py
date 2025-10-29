"""
Cache Manager
=============

Manages caching of API responses and search results to reduce redundant queries.
Implements TTL-based expiration and efficient storage.
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional


class CacheManager:
    """
    Simple file-based cache with TTL support.
    Reduces redundant API calls and respects rate limits.
    """

    def __init__(self, cache_dir: str, default_ttl: int = 3600):
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time-to-live in seconds (default: 1 hour)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

    def _get_cache_path(self, key: str) -> Path:
        """Generate cache file path from key."""
        # Hash the key to create safe filename
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve value from cache if exists and not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)

            # Check if expired
            if cache_data.get('expires_at', 0) < time.time():
                cache_path.unlink()  # Delete expired cache
                return None

            return cache_data.get('value')

        except (json.JSONDecodeError, IOError):
            # Invalid cache file, delete it
            cache_path.unlink(missing_ok=True)
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Store value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            ttl: Time-to-live in seconds (uses default if None)
        """
        cache_path = self._get_cache_path(key)
        ttl = ttl if ttl is not None else self.default_ttl

        cache_data = {
            'key': key,
            'value': value,
            'cached_at': time.time(),
            'expires_at': time.time() + ttl
        }

        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except (IOError, TypeError) as e:
            # Cache write failed, continue without caching
            pass

    def has(self, key: str) -> bool:
        """Check if key exists in cache and is not expired."""
        return self.get(key) is not None

    def delete(self, key: str):
        """Delete cache entry."""
        cache_path = self._get_cache_path(key)
        cache_path.unlink(missing_ok=True)

    def clear_expired(self):
        """Remove all expired cache entries."""
        current_time = time.time()
        deleted_count = 0

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)

                if cache_data.get('expires_at', 0) < current_time:
                    cache_file.unlink()
                    deleted_count += 1

            except (json.JSONDecodeError, IOError):
                # Invalid cache file
                cache_file.unlink(missing_ok=True)
                deleted_count += 1

        return deleted_count

    def clear_all(self):
        """Remove all cache entries."""
        deleted_count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            deleted_count += 1
        return deleted_count

    def get_stats(self) -> dict:
        """Get cache statistics."""
        total = 0
        expired = 0
        valid = 0
        current_time = time.time()

        for cache_file in self.cache_dir.glob("*.json"):
            total += 1
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)

                if cache_data.get('expires_at', 0) < current_time:
                    expired += 1
                else:
                    valid += 1

            except (json.JSONDecodeError, IOError):
                expired += 1

        return {
            'total_entries': total,
            'valid_entries': valid,
            'expired_entries': expired
        }
