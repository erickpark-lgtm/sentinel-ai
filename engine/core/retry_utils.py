"""
SentinelAI API Resilience & Exponential Backoff Engine
Provides rate-limiting defense, full-jitter exponential backoff,
and transparent retries for GitHub, AWS, and Cloud API calls.
"""

import time
import random
import urllib.error
from typing import Callable, Any, Optional

def with_exponential_backoff(
    max_retries: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0
):
    """
    Decorator implementing full-jitter exponential backoff.
    Automatically handles HTTP 429 (Rate Limit), 403 (Throttling), and 5xx transient server errors.
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs) -> Any:
            attempt = 0
            while attempt < max_retries:
                try:
                    result = func(*args, **kwargs)
                    # If function returns a tuple of (status, data), check HTTP status
                    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], int):
                        status, data = result
                        if status in (429, 403, 500, 502, 503, 504):
                            # Check if 403 is actually a rate-limit error
                            is_rate_limit = False
                            if status == 429:
                                is_rate_limit = True
                            elif status == 403 and isinstance(data, dict):
                                msg = str(data.get("message", "")).lower()
                                if "rate limit" in msg or "secondary rate limit" in msg:
                                    is_rate_limit = True

                            if is_rate_limit or status >= 500:
                                attempt += 1
                                if attempt >= max_retries:
                                    return result
                                # Calculate jittered delay
                                delay = min(max_delay, base_delay * (backoff_factor ** attempt))
                                sleep_time = random.uniform(0.5 * delay, delay)
                                time.sleep(sleep_time)
                                continue
                    return result

                except urllib.error.HTTPError as err:
                    attempt += 1
                    if attempt >= max_retries:
                        raise err
                    if err.code in (429, 403, 500, 502, 503, 504):
                        retry_after = err.headers.get("Retry-After") if err.headers else None
                        if retry_after and retry_after.isdigit():
                            sleep_time = float(retry_after)
                        else:
                            delay = min(max_delay, base_delay * (backoff_factor ** attempt))
                            sleep_time = random.uniform(0.5 * delay, delay)
                        time.sleep(sleep_time)
                    else:
                        raise err

                except (urllib.error.URLError, TimeoutError, ConnectionError) as net_err:
                    attempt += 1
                    if attempt >= max_retries:
                        raise net_err
                    delay = min(max_delay, base_delay * (backoff_factor ** attempt))
                    sleep_time = random.uniform(0.5 * delay, delay)
                    time.sleep(sleep_time)

            return func(*args, **kwargs)
        return wrapper
    return decorator
