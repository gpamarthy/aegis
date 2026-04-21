"""Auto-discover LLM chat endpoints from a target URL.

Crawls the page HTML and JavaScript bundles to find API endpoints
that look like LLM/chatbot interfaces, then probes them to confirm.
"""

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


@dataclass
class DiscoveryResult:
    base_url: str = ""
    send_endpoint: str = ""
    send_method: str = "POST"
    send_field: str = "content"
    receive_endpoint: str = ""
    receive_method: str = "GET"
    response_field: str = "content"
    sender_field: str = "sender"
    bot_sender_value: str = "Bot"
    bot_name: str = "Unknown AI"
    description: str = ""
    confirmed: bool = False
    auth_type: str = ""  # "jwt", "cookie", "none"
    access_token: str = ""
    csrf_token: str = ""
    content_type: str = "json"  # "json" or "form"


# Patterns that suggest a chat/message send endpoint
# hack: regex is brittle, should use proper OpenAPI parser
_SEND_PATTERNS = [
    r'"/api/messages/send"',
    r'"/api/chat/send"',
    r'"/api/chat"',
    r'"/api/send"',
    r'"/api/message"',
    r'"/api/completion"',
    r'"/api/ask"',
    r'"/api/query"',
    r'"/api/prompt"',
    r'"/api/v1/chat"',
    r'"/api/v1/messages"',
    r'"/chat/send"',
    r'"/chat/message"',
    r'"/send-message"',
    r'"/api/bot/chat"',
    r'"/api/assistant"',
    r'"/process"',
    r'"/chat"',
    r'"/ask"',
    r'"/query"',
]

# Patterns that suggest a chat/message receive/list endpoint
_RECEIVE_PATTERNS = [
    r'"/api/messages"',
    r'"/api/chat/messages"',
    r'"/api/chat/history"',
    r'"/api/history"',
    r'"/api/conversations"',
    r'"/api/v1/messages"',
    r'"/chat/messages"',
    r'"/chat/history"',
]

# Patterns to extract the field name used for sending message content
_FIELD_PATTERNS = [
    r'\{["\']?(content|message|text|prompt|query|input|question)["\']?\s*:',
    r'body:\s*JSON\.stringify\(\{["\']?(content|message|text|prompt|query)["\']?',
]

# Patterns to identify the bot/AI identity from page content
_BOT_IDENTITY_PATTERNS = [
    r'<title[^>]*>([^<]+)</title>',
    r'(?:chat with|talk to|ask)\s+(?:our\s+)?(.+?)(?:\s+ai|\s+bot|\s+assistant)',
    r'(?:ai|bot|assistant)\s+(?:name|called|named)\s*[:\-]?\s*["\']?([^"\'<,]+)',
]


async def discover_llm_endpoint(target_url: str, timeout: float = 15.0) -> DiscoveryResult:
    """Discover LLM chat endpoint from a target URL.

    1. Fetches the main page HTML
    2. Extracts JS bundle URLs
    3. Scans HTML + JS for API endpoint patterns
    4. Probes discovered endpoints to confirm they work
    5. Determines the request/response format
    """
    result = DiscoveryResult(base_url=target_url.rstrip("/"))

    target_host = urlparse(target_url).hostname

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
        # Step 1: Fetch main page
        try:
            resp = await client.get(target_url)
            html = resp.text
        except Exception:
            return result

        # Detect JWT/CSRF authentication from Set-Cookie headers
        # Check CSRF first to avoid csrf_access_token matching as access_token
        for cookie_name, cookie_value in resp.cookies.items():
            if "csrf" in cookie_name.lower():
                result.csrf_token = cookie_value
            elif "access_token" in cookie_name or "session" in cookie_name.lower():
                result.access_token = cookie_value
                result.auth_type = "jwt"

        # Extract bot identity from page
        for pattern in _BOT_IDENTITY_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                result.bot_name = match.group(1).strip()
                break

        # Extract description
        desc_match = re.search(r'<meta\s+name="description"\s+content="([^"]+)"', html)
        if desc_match:
            result.description = desc_match.group(1)

        # Step 2: Collect all text to search (HTML + JS from all reachable pages)
        searchable = html
        pages_checked = {"/"}

        # Also extract inline script content
        inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html)
        for script in inline_scripts:
            searchable += "\n" + script

        # Follow internal links to find more pages with JS/API refs
        # Only follow relative paths (starts with /) to prevent SSRF
        internal_links = re.findall(r'href="(/[^"]*\.html?)"', html)
        internal_links += re.findall(r"href='(/[^']*\.html?)'", html)
        # Filter out links that try path traversal or protocol smuggling
        internal_links = [l for l in internal_links if not l.startswith("//") and ".." not in l]
        for link in internal_links[:5]:
            if link in pages_checked:
                continue
            pages_checked.add(link)
            try:
                link_cookies = {}
                if result.access_token:
                    link_cookies["access_token_cookie"] = result.access_token
                if result.csrf_token:
                    link_cookies["csrf_access_token"] = result.csrf_token
                link_resp = await client.get(
                    f"{result.base_url}{link}", cookies=link_cookies,
                )
                if link_resp.status_code == 200 and "text/html" in link_resp.headers.get("content-type", ""):
                    searchable += "\n" + link_resp.text
                    # Extract JS from linked pages too
                    link_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', link_resp.text)
                    for s in link_scripts:
                        searchable += "\n" + s
                    # Find JS src tags in linked pages (only relative paths)
                    for src in re.findall(r'src=["\']([^"\']+\.js)["\']', link_resp.text):
                        if src.startswith("http"):
                            # Only allow JS from same host
                            if urlparse(src).hostname != target_host:
                                continue
                        else:
                            src = "/" + src.lstrip("/")
                        try:
                            js_r = await client.get(f"{result.base_url}{src}")
                            if js_r.status_code == 200:
                                searchable += "\n" + js_r.text
                        except Exception:
                            pass
            except Exception:
                pass

        # Find JS bundle URLs from main page (various patterns)
        js_urls = re.findall(r'src="(/_next/static/chunks/[^"]+\.js)"', html)
        js_urls += re.findall(r"src='(/_next/static/chunks/[^']+\.js)'", html)
        js_urls += re.findall(r'src="(/static/[^"]+\.js)"', html)
        js_urls += re.findall(r'src="(/assets/[^"]+\.js)"', html)
        js_urls += re.findall(r'src="(/js/[^"]+\.js)"', html)
        js_urls += re.findall(r'"(static/chunks/[^"]+\.js)"', html)

        # Also try common JS paths if nothing found
        if not js_urls:
            for common in ["/static/script.js", "/static/app.js", "/static/main.js",
                           "/js/app.js", "/js/main.js", "/assets/js/app.js"]:
                try:
                    probe = await client.get(f"{result.base_url}{common}")
                    if probe.status_code == 200 and "javascript" in probe.headers.get("content-type", ""):
                        js_urls.append(common)
                except Exception:
                    pass

        priority_js = [u for u in js_urls if "page" in u or "app" in u]
        other_js = [u for u in js_urls if u not in priority_js]

        for js_url in priority_js + other_js[:15]:
            full_url = js_url if js_url.startswith("/") else f"/_next/{js_url}"
            try:
                js_resp = await client.get(f"{result.base_url}{full_url}")
                searchable += "\n" + js_resp.text
            except Exception:
                continue

        # Step 3: Find send endpoint
        send_url = ""
        for pattern in _SEND_PATTERNS:
            match = re.search(pattern, searchable)
            if match:
                send_url = match.group(0).strip('"')
                break

        # Fallback: find any /api/ path with fetch + POST
        if not send_url:
            api_matches = re.findall(r'"(/api/[^"]{3,50})"', searchable)
            for candidate in api_matches:
                # Look for POST method near this URL in the source
                idx = searchable.find(f'"{candidate}"')
                if idx >= 0:
                    context = searchable[max(0, idx - 200):idx + 200]
                    if re.search(r'method\s*:\s*["\']POST["\']', context, re.IGNORECASE):
                        send_url = candidate
                        break

        if not send_url:
            return result

        result.send_endpoint = f"{result.base_url}{send_url}"

        # Step 4: Find receive endpoint
        for pattern in _RECEIVE_PATTERNS:
            match = re.search(pattern, searchable)
            if match:
                recv_url = match.group(0).strip('"')
                result.receive_endpoint = f"{result.base_url}{recv_url}"
                break

        # Fallback: derive receive from send (e.g., /api/messages/send -> /api/messages)
        if not result.receive_endpoint:
            if "/send" in send_url:
                recv_url = send_url.rsplit("/send", 1)[0]
                result.receive_endpoint = f"{result.base_url}{recv_url}"

        # Build auth for probing
        probe_cookies = {}
        probe_headers = {}
        if result.access_token:
            probe_cookies["access_token_cookie"] = result.access_token
        if result.csrf_token:
            probe_cookies["csrf_access_token"] = result.csrf_token
            probe_headers["X-CSRF-TOKEN"] = result.csrf_token

        # Step 5: Determine send field + content type by probing the API
        # Try both form-data and JSON with common field names
        probed_field = False
        for ctype in ["json", "form"]:
            for test_field in ["content", "text", "message", "prompt", "query", "input"]:
                try:
                    if ctype == "form":
                        test_resp = await client.post(
                            result.send_endpoint,
                            data={test_field: "hello"},
                            headers=probe_headers,
                            cookies=probe_cookies,
                        )
                    else:
                        test_resp = await client.post(
                            result.send_endpoint,
                            json={test_field: "hello"},
                            headers={**probe_headers, "Content-Type": "application/json"},
                            cookies=probe_cookies,
                        )

                    if test_resp.status_code == 429:
                        await asyncio.sleep(7)
                        # Retry same field after rate limit
                        if ctype == "json":
                            test_resp = await client.post(
                                result.send_endpoint,
                                json={test_field: "hello"},
                                headers={**probe_headers, "Content-Type": "application/json"},
                                cookies=probe_cookies,
                            )
                        else:
                            test_resp = await client.post(
                                result.send_endpoint,
                                data={test_field: "hello"},
                                headers=probe_headers,
                                cookies=probe_cookies,
                            )
                        if test_resp.status_code == 429:
                            await asyncio.sleep(7)
                            continue

                    if test_resp.status_code in (200, 201):
                        # Check body for error indicators (API returned 200 but field was wrong)
                        body_text = test_resp.text.strip().lower()
                        if '"error"' in body_text or "'error'" in body_text:
                            try:
                                err_data = test_resp.json()
                                if "error" in err_data:
                                    # This field was wrong, the API told us
                                    continue
                            except Exception:
                                pass
                        result.send_field = test_field
                        result.content_type = ctype
                        probed_field = True
                        # If response is plain text (not JSON list/obj), it's direct-response
                        resp_text = test_resp.text.strip()
                        try:
                            parsed = test_resp.json()
                            if isinstance(parsed, dict) and "message" in parsed:
                                # {"message": "delivered"} style - still need receive
                                pass
                            elif isinstance(parsed, list):
                                pass
                            else:
                                result.receive_endpoint = ""
                        except Exception:
                            # Plain text = direct response API
                            if resp_text and len(resp_text) < 5000:
                                result.receive_endpoint = ""
                        break

                    if test_resp.status_code == 400:
                        body = test_resp.text.lower()
                        for candidate in ["content", "message", "text", "prompt"]:
                            if f'"{candidate}" is required' in body or f"'{candidate}' is required" in body:
                                result.send_field = candidate
                                result.content_type = ctype
                                probed_field = True
                                break
                        if probed_field:
                            break
                except Exception:
                    continue
            if probed_field:
                break

        # Fallback to regex
        if not probed_field:
            for pattern in _FIELD_PATTERNS:
                match = re.search(pattern, searchable, re.IGNORECASE)
                if match:
                    result.send_field = match.group(1)
                    break

        # Step 6: Probe the receive endpoint to confirm format
        if result.receive_endpoint:
            try:
                probe_resp = await client.get(result.receive_endpoint, cookies=probe_cookies)
                if probe_resp.status_code == 200:
                    data = probe_resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        first = data[0]
                        for field_name in ["content", "message", "text", "response", "body"]:
                            if field_name in first:
                                result.response_field = field_name
                                break
                        for field_name in ["sender", "role", "type", "author", "from"]:
                            if field_name in first:
                                result.sender_field = field_name
                                val = first[field_name]
                                if isinstance(val, str) and val.lower() in ("bot", "assistant", "ai", "system"):
                                    result.bot_sender_value = val
                                break
                        result.confirmed = True
            except Exception:
                pass

        # Step 7: Mark confirmed if probing succeeded
        if not result.confirmed and probed_field:
            result.confirmed = True

    return result
