import time
import urllib.request


def fetch_with_retry(url):
    for attempt in range(MAX_RETRIES):
        try:
            return urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT).read()
        except OSError as error:
            logger.warning("attempt %s failed: %s", attempt + 1, error)
            time.sleep(BACKOFF_SECONDS)
    raise RuntimeError("all retries failed")
