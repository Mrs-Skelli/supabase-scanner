import logging
import os
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
BUILTWITH_LISTS_URL = 'https://api.builtwith.com/lists12/api.json'
DEFAULT_TECH = os.environ.get('BUILTWITH_TECH', 'Supabase')


def _normalize_domain(domain: str) -> str | None:
    if not domain:
        return None
    domain = domain.strip().lower()
    if '://' in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    domain = domain.strip('/')
    if not domain:
        return None
    return f'https://{domain}'


async def discover_targets(max_results: int = 500, tech: str | None = None, include_meta: bool = False) -> list[dict]:
    api_key = os.environ.get('BUILTWITH_API_KEY')
    if not api_key:
        logger.info('BUILTWITH_API_KEY not configured, skipping BuiltWith source')
        return []

    tech = tech or DEFAULT_TECH
    offset = None
    results: list[dict] = []
    seen: set[str] = set()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        while len(results) < max_results:
            params = {
                'KEY': api_key,
                'TECH': tech.replace(' ', '-'),
            }
            if include_meta:
                params['META'] = 'yes'
            if offset:
                params['OFFSET'] = offset
            try:
                resp = await client.get(BUILTWITH_LISTS_URL, params=params, timeout=30)
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:
                logger.warning('BuiltWith request failed: %s', exc)
                break

            for item in payload.get('Results', []):
                domain = item.get('D')
                normalized = _normalize_domain(domain)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                results.append({
                    'url': normalized,
                    'source': 'builtwith',
                    'metadata': {
                        'tech': tech,
                        'domain': domain,
                        'first_detected': item.get('FD'),
                        'last_detected': item.get('LD'),
                    },
                })
                if len(results) >= max_results:
                    break

            offset = payload.get('NextOffset')
            if not offset or offset == 'END':
                break
    return results
