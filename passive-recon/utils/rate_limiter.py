"""
Rate Limiter
============

Implements rate limiting to respect API quotas and avoid triggering
anti-bot protections on search engines and services.
"""

import time
import random
from collections import deque
from typing import Dict, Optional


class RateLimiter:
    """
    Token bucket rate limiter with per-service limits.
    Implements exponential backoff and jitter.
    """

    def __init__(self, rate_limits: Dict[str, Dict]):
        """
        Initialize rate limiter.

        Args:
            rate_limits: Dictionary of service -> config
                Example: {
                    'google': {'requests_per_minute': 10, 'burst': 3},
                    'github': {'requests_per_hour': 60}
                }
        """
        self.rate_limits = rate_limits
        self.request_history = {}  # service -> deque of timestamps
        self.backoff_state = {}  # service -> backoff level

    def wait_if_needed(self, service: str):
        """
        Block if rate limit would be exceeded.
        Implements intelligent backoff with jitter.

        Args:
            service: Name of the service being rate-limited
        """
        if service not in self.rate_limits:
            # No rate limit configured, add small random delay
            time.sleep(random.uniform(0.5, 1.5))
            return

        config = self.rate_limits[service]
        now = time.time()

        # Initialize history for this service
        if service not in self.request_history:
            self.request_history[service] = deque()

        history = self.request_history[service]

        # Determine rate limit parameters
        window_seconds = self._get_window_seconds(config)
        max_requests = self._get_max_requests(config)

        # Remove old requests outside the window
        cutoff_time = now - window_seconds
        while history and history[0] < cutoff_time:
            history.popleft()

        # Check if we need to wait
        if len(history) >= max_requests:
            # Rate limit hit, calculate wait time
            oldest_request = history[0]
            wait_time = (oldest_request + window_seconds) - now

            if wait_time > 0:
                # Add jitter to avoid thundering herd
                jitter = random.uniform(0, min(wait_time * 0.1, 1.0))
                total_wait = wait_time + jitter

                # Apply exponential backoff if we've been hitting limits
                backoff_level = self.backoff_state.get(service, 0)
                if backoff_level > 0:
                    backoff_multiplier = 2 ** min(backoff_level, 5)
                    total_wait *= backoff_multiplier

                time.sleep(total_wait)

                # Increment backoff
                self.backoff_state[service] = backoff_level + 1

        # Record this request
        history.append(now)

        # Reset backoff if we haven't hit limits recently
        if len(history) < max_requests * 0.8:
            self.backoff_state[service] = 0

        # Add small random delay between requests
        base_delay = config.get('min_delay', 1.0)
        time.sleep(random.uniform(base_delay, base_delay * 1.5))

    def _get_window_seconds(self, config: Dict) -> int:
        """Extract rate limit window in seconds."""
        if 'requests_per_second' in config:
            return 1
        elif 'requests_per_minute' in config:
            return 60
        elif 'requests_per_hour' in config:
            return 3600
        elif 'requests_per_day' in config:
            return 86400
        else:
            return 60  # Default to 1 minute

    def _get_max_requests(self, config: Dict) -> int:
        """Extract maximum requests for the window."""
        return (config.get('requests_per_second') or
                config.get('requests_per_minute') or
                config.get('requests_per_hour') or
                config.get('requests_per_day') or
                10)  # Default to 10 requests

    def get_stats(self, service: str) -> Dict:
        """Get rate limiting statistics for a service."""
        if service not in self.request_history:
            return {
                'requests_made': 0,
                'backoff_level': 0
            }

        config = self.rate_limits.get(service, {})
        window = self._get_window_seconds(config)
        now = time.time()
        cutoff = now - window

        # Count recent requests
        recent_requests = sum(1 for ts in self.request_history[service] if ts > cutoff)

        return {
            'requests_made': recent_requests,
            'window_seconds': window,
            'max_requests': self._get_max_requests(config),
            'backoff_level': self.backoff_state.get(service, 0)
        }

    def reset(self, service: Optional[str] = None):
        """Reset rate limit history for a service or all services."""
        if service:
            self.request_history.pop(service, None)
            self.backoff_state.pop(service, None)
        else:
            self.request_history.clear()
            self.backoff_state.clear()
