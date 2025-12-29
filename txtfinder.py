#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

def log_err(msg: str, debug: bool) -> None:
    if debug:
        print(msg)
    else:
        print(msg, file=sys.stderr)


def log_dbg(msg: str, debug: bool) -> None:
    if debug:
        print(f"[debug] {msg}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="txtfinder.py",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Query Shodan DNS data for target domains and find TXT records\n"
            "containing a search string."
        ),
        epilog=(
            "Examples:\n"
            "  ./txtfinder.py -i scope.txt -s \"ms=\"\n"
            "  ./txtfinder.py -i scope.txt -s \"google-site-verification\" --debug\n"
        ),
    )
    parser.add_argument("-i", dest="input_file", help="Input scope file (required).")
    parser.add_argument("-s", dest="search_string", help="Search string (required).")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("-h", "--help", action="store_true", dest="help_flag", help="Show this help and exit.")
    return parser


def print_help_if_requested(parser: argparse.ArgumentParser, argv) -> None:
    if any(arg in ("-h", "--help") for arg in argv):
        parser.print_help()
        sys.exit(0)


def read_lines(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            yield line


def normalize_domain(raw: str) -> str:
    value = raw.strip()
    if "://" in value:
        value = urllib.parse.urlparse(value).netloc or value
    value = value.split("/", 1)[0].strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def core_domain(domain: str) -> str:
    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return domain
    sld_tlds = {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "co.nz",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "com.br",
        "com.mx",
        "com.tr",
        "com.cn",
        "com.hk",
        "com.sg",
    }
    last_two = ".".join(parts[-2:])
    if last_two in sld_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def redact_url(url: str) -> str:
    if "key=" not in url:
        return url
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(k, "REDACTED" if k == "key" else v) for k, v in query]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(redacted), parts.fragment)
    )


def shodan_get(url: str, debug: bool) -> tuple[str, int]:
    attempt = 0
    max_attempts = 5
    delay = 1
    while attempt < max_attempts:
        attempt += 1
        log_dbg(f"Shodan request (attempt {attempt}/{max_attempts}): {redact_url(url)}", debug)
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.getcode()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            log_err(f"Request failed: {redact_url(url)}", debug)
            return ("", 0)

        if status == 200:
            log_dbg(f"Shodan response 200 for: {redact_url(url)}", debug)
            return (body, status)

        if status == 429 or "rate limit" in body.lower():
            log_dbg(f"Rate limited (status {status}); backing off {delay}s", debug)
            time.sleep(delay)
            delay *= 2
            continue

        log_err(f"Shodan API error ({status}): {redact_url(url)}", debug)
        return ("", status)

    log_err(f"Shodan API rate limit exceeded: {redact_url(url)}", debug)
    return ("", 429)


def shodan_api_info(api_key: str, debug: bool) -> tuple[str, int]:
    url = f"https://api.shodan.io/api-info?key={api_key}"
    return shodan_get(url, debug)


def load_shodan_key_file() -> str:
    path = os.path.expanduser("~/.shodan/api_key")
    if not os.path.isfile(path):
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def print_header() -> None:
    print(f"{'DOMAIN':<30} TXT")
    print(f"{'------':<30} ---")


def main(argv) -> int:
    parser = build_parser()
    print_help_if_requested(parser, argv)
    args = parser.parse_args(argv)

    if not args.input_file or not args.search_string:
        log_err("Missing required inputs.", args.debug)
        parser.print_help()
        return 1

    env_key = os.environ.get("SHODANAPI", "").strip()
    file_key = load_shodan_key_file()
    api_key = env_key or file_key
    fallback_key = file_key if env_key and file_key and env_key != file_key else ""
    if not api_key:
        log_err("No Shodan API key found in SHODANAPI or ~/.shodan/api_key.", args.debug)
        return 1
    info_body, info_status = shodan_api_info(api_key, args.debug)
    if info_status == 401 and fallback_key:
        log_dbg("401 with SHODANAPI; retrying api-info with ~/.shodan/api_key", args.debug)
        info_body, info_status = shodan_api_info(fallback_key, args.debug)
        if info_status == 200:
            api_key = fallback_key
    if info_status == 200 and info_body:
        try:
            info_data = json.loads(info_body)
            print(json.dumps(info_data, indent=2, sort_keys=True))
        except json.JSONDecodeError:
            log_err("Invalid JSON from Shodan api-info.", args.debug)
    else:
        log_err("Unable to fetch Shodan api-info; continuing.", args.debug)

    if not os.path.isfile(args.input_file):
        log_err(f"Cannot read input file: {args.input_file}", args.debug)
        return 1

    needle = args.search_string.lower()
    queried = set()

    print_header()

    for domain in read_lines(args.input_file):
        raw_domain = domain
        domain = normalize_domain(domain)
        if not domain:
            continue
        core = core_domain(domain)
        if core in queried:
            log_dbg(f"Skipping duplicate core domain: {core} (input: {raw_domain})", args.debug)
            continue
        queried.add(core)
        if core != domain:
            log_dbg(f"Using core domain {core} for input {domain}", args.debug)
        log_dbg(f"Processing domain: {core}", args.debug)

        url = (
            "https://api.shodan.io/dns/domain/"
            f"{core}?key={api_key}&type=TXT&page=1&history=false"
        )
        body, status = shodan_get(url, args.debug)
        if status == 401 and fallback_key:
            log_dbg("401 with SHODANAPI; retrying with ~/.shodan/api_key", args.debug)
            url = (
                "https://api.shodan.io/dns/domain/"
                f"{core}?key={fallback_key}&type=TXT&page=1&history=false"
            )
            body, status = shodan_get(url, args.debug)
        if not body:
            if status == 401:
                log_err(f"Shodan API unauthorized; check API key. Skipping domain: {core}", args.debug)
            else:
                log_err(f"Skipping domain (unresolved): {core}", args.debug)
            continue

        try:
            data = json.loads(body)
        except Exception:
            log_err(f"Invalid JSON from Shodan for domain: {core}", args.debug)
            continue

        records = data.get("data", [])
        matched = 0
        for entry in records:
            rec_type = entry.get("type")
            if rec_type != "TXT":
                continue
            value = entry.get("value") or ""
            if needle not in value.lower():
                continue
            matched += 1
            print(f"{core:<30} {value}")
        if matched == 0:
            log_dbg(f"No TXT records matching '{args.search_string}' for {core}", args.debug)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
