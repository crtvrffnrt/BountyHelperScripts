#!/usr/bin/env python3
import argparse
import csv
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import urllib.parse


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
        prog="subtaker.py",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Query Shodan DNS data for target domains and match results against\n"
            "suffix fragments. Emits a live table to stdout and optionally writes\n"
            "JSON/CSV output files."
        ),
        epilog=(
            "Examples:\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt -O json --output out.json\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt --deadcheck --debug\n"
        ),
    )
    parser.add_argument("-i", dest="input_file", help="Input scope file (required).")
    parser.add_argument("-d", dest="fragments_file", help="Suffix fragments file (required).")
    parser.add_argument(
        "-O",
        dest="out_format",
        default="table",
        choices=["table", "json", "csv"],
        help="Output file format when --output is used. Default: table.",
    )
    parser.add_argument("--output", dest="out_file", default="", help="Write JSON/CSV to this file.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--deadcheck", action="store_true", help="Check HTTP/HTTPS liveness.")
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


def load_suffixes(path: str):
    suffixes = []
    for line in read_lines(path):
        normalized = "".join(line.split()).lower().rstrip(".")
        if normalized:
            suffixes.append(normalized)
    return suffixes


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


def is_suffix_match(host: str, suffixes) -> bool:
    if not host:
        return False
    host = host.rstrip(".").lower()
    for suffix in suffixes:
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


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


def load_shodan_key_file() -> str:
    path = os.path.expanduser("~/.shodan/api_key")
    if not os.path.isfile(path):
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def check_live(host: str, timeout: int) -> tuple:
    if not host:
        return ("dead", "")

    https_ctx = ssl._create_unverified_context()
    for proto, ctx in (("https", https_ctx), ("http", None)):
        url = f"{proto}://{host}"
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx):
                return ("live", proto)
        except Exception:
            continue
    return ("dead", "")


def print_header(deadcheck: bool) -> None:
    if deadcheck:
        print(f"{'DOMAIN':<30} {'SUBDOMAIN':<45} {'VALUE':<45} {'LIVE':<6} PROTO")
        print(f"{'------':<30} {'---------':<45} {'-----':<45} {'----':<6} -----")
    else:
        print(f"{'DOMAIN':<30} {'SUBDOMAIN':<45} VALUE")
        print(f"{'------':<30} {'---------':<45} -----")


def main(argv) -> int:
    parser = build_parser()
    print_help_if_requested(parser, argv)
    args = parser.parse_args(argv)

    if not args.input_file or not args.fragments_file:
        log_err("Missing required input files.", args.debug)
        parser.print_help()
        return 1

    env_key = os.environ.get("SHODANAPI", "").strip()
    file_key = load_shodan_key_file()
    api_key = env_key or file_key
    fallback_key = file_key if env_key and file_key and env_key != file_key else ""
    if not api_key:
        log_err("No Shodan API key found in SHODANAPI or ~/.shodan/api_key.", args.debug)
        return 1

    if not os.path.isfile(args.input_file):
        log_err(f"Cannot read input file: {args.input_file}", args.debug)
        return 1
    if not os.path.isfile(args.fragments_file):
        log_err(f"Cannot read fragments file: {args.fragments_file}", args.debug)
        return 1

    suffixes = load_suffixes(args.fragments_file)
    dedupe = set()
    results = []

    print_header(args.deadcheck)

    queried = set()
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
            f"{core}?key={api_key}&type=CNAME&page=1&history=false"
        )
        body, status = shodan_get(url, args.debug)
        if status == 401 and fallback_key:
            log_dbg("401 with SHODANAPI; retrying with ~/.shodan/api_key", args.debug)
            url = (
                "https://api.shodan.io/dns/domain/"
                f"{core}?key={fallback_key}&type=CNAME&page=1&history=false"
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
        except json.JSONDecodeError:
            log_err(f"Invalid JSON from Shodan for domain: {core}", args.debug)
            continue

        records = data.get("data", [])
        seen = 0
        for entry in records:
            if seen >= 100:
                log_dbg(f"CNAME cap reached for {core}; skipping remaining records", args.debug)
                break
            rec_type = entry.get("type")
            if rec_type != "CNAME":
                continue
            sub = entry.get("subdomain") or ""
            value = entry.get("value") or ""
            fqdn = f"{sub}.{core}" if sub else core

            seen += 1
            log_dbg(f"CNAME {fqdn} -> {value}", args.debug)
            if not is_suffix_match(value, suffixes):
                log_dbg(f"No suffix match for {fqdn} -> {value}", args.debug)
                continue
            log_dbg(f"Matched suffix for {fqdn} -> {value}", args.debug)
            key = f"{core}|{fqdn}|{value}"
            if key in dedupe:
                continue
            dedupe.add(key)
            live_state, live_proto = ("", "")
            if args.deadcheck:
                live_state, live_proto = check_live(value, 10)
            results.append(
                {
                    "domain": core,
                    "subdomain": fqdn,
                    "value": value,
                    "live": live_state,
                    "proto": live_proto,
                }
            )
            if args.deadcheck:
                print(
                    f"{domain:<30} {fqdn:<45} {value:<45} {live_state:<6} {live_proto}"
                )
            else:
                print(f"{domain:<30} {fqdn:<45} {value}")

    if args.out_file and args.out_format in ("json", "csv"):
        if args.out_format == "json":
            payload = []
            for item in results:
                if args.deadcheck:
                    payload.append(
                        {
                            "domain": item["domain"],
                            "subdomain": item["subdomain"],
                            "value": item["value"],
                            "live": item["live"],
                            "proto": item["proto"],
                        }
                    )
                else:
                    payload.append(
                        {
                            "domain": item["domain"],
                            "subdomain": item["subdomain"],
                            "value": item["value"],
                        }
                    )
            with open(args.out_file, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
        else:
            with open(args.out_file, "w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                if args.deadcheck:
                    writer.writerow(["domain", "subdomain", "value", "live", "proto"])
                    for item in results:
                        writer.writerow(
                            [
                                item["domain"],
                                item["subdomain"],
                                item["value"],
                                item["live"],
                                item["proto"],
                            ]
                        )
                else:
                    writer.writerow(["domain", "subdomain", "value"])
                    for item in results:
                        writer.writerow(
                            [item["domain"], item["subdomain"], item["value"]]
                        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
