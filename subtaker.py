#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import ssl
import subprocess
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
    parser.add_argument(
        "--onlydead",
        action="store_true",
        help="Only output dead endpoints and check Traffic Manager registerability.",
    )
    parser.add_argument(
        "-scope",
        dest="scope",
        choices=["trafficmanager", "storage", "websites", "frontdoor"],
        help="Filter CNAME targets by product (trafficmanager, storage, websites, frontdoor).",
    )
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


def shodan_api_info(api_key: str, debug: bool) -> tuple[str, int]:
    url = f"https://api.shodan.io/api-info?key={api_key}"
    return shodan_get(url, debug)


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
            log_dbg(f"Request failed: {redact_url(url)}", debug)
            return ("", 0)

        if status == 200:
            log_dbg(f"Shodan response 200 for: {redact_url(url)}", debug)
            return (body, status)

        if status == 429 or "rate limit" in body.lower():
            log_dbg(f"Rate limited (status {status}); backing off {delay}s", debug)
            time.sleep(delay)
            delay *= 2
            continue

        log_dbg(f"Shodan API error ({status}): {redact_url(url)}", debug)
        return ("", status)

    log_dbg(f"Shodan API rate limit exceeded: {redact_url(url)}", debug)
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

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            return ("live", "icmp")
    except Exception:
        pass

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


def check_registerable(host: str, debug: bool) -> str:
    hostname = host.rstrip(".").lower()
    suffix = ".trafficmanager.net"
    if not hostname.endswith(suffix):
        return ""
    name = hostname[: -len(suffix)].strip(".")
    if not name:
        return ""
    try:
        result = subprocess.run(
            ["az", "network", "traffic-manager", "profile", "check-dns", "--name", name],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        log_dbg(f"az check-dns failed for {name}", debug)
        return ""
    if result.returncode != 0:
        log_dbg(f"az check-dns error for {name}: {result.stderr.strip()}", debug)
        return ""
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        log_dbg(f"az check-dns returned invalid JSON for {name}", debug)
        return ""
    available = payload.get("nameAvailable")
    if available is True:
        return "yes"
    if available is False:
        return "no"
    return ""


FRONTDOOR_SUFFIXES = ("azurefd.net",)
FRONTDOOR_RG_NAME = "MSOBB"
FRONTDOOR_API_VER = "2025-04-15"
FRONTDOOR_TYPE = "Microsoft.Cdn/Profiles/AfdEndpoints"
FRONTDOOR_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
SCOPE_SUFFIXES = {
    "trafficmanager": ("trafficmanager.net",),
    "storage": ("core.windows.net",),
    "websites": ("azurewebsites.net",),
    "frontdoor": FRONTDOOR_SUFFIXES,
}


def extract_hostname(raw: str) -> str:
    host = raw.strip().lower()
    if not host:
        return ""
    if "://" in host:
        host = urllib.parse.urlparse(host).netloc or host
    host = host.split("/", 1)[0]
    host = host.split("#", 1)[0]
    host = host.split("?", 1)[0]
    return host.strip().rstrip(".")


def is_frontdoor_host(host: str) -> bool:
    if not host:
        return False
    for suffix in FRONTDOOR_SUFFIXES:
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


def get_frontdoor_subscription_id(debug: bool) -> str:
    try:
        result = subprocess.run(
            ["az", "account", "show", "--query", "id", "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        log_dbg("az account show failed for frontdoor check", debug)
        return ""
    if result.returncode != 0:
        log_dbg(f"az account show error: {result.stderr.strip()}", debug)
        return ""
    return result.stdout.strip()


def check_frontdoor_availability(host: str, debug: bool, sub_id: str) -> tuple[str, str, str]:
    hostname = extract_hostname(host)
    if not is_frontdoor_host(hostname):
        return ("", "", "")
    endpoint = hostname.split(".", 1)[0]
    if not FRONTDOOR_LABEL_RE.match(endpoint):
        return ("false", "invalid_label", "invalid endpoint label")
    if not sub_id:
        log_dbg(f"Missing subscription id for frontdoor check: {hostname}", debug)
        return ("", "az_unavailable", "unable to resolve subscription id")
    url = (
        "https://management.azure.com/subscriptions/"
        f"{sub_id}/resourceGroups/{FRONTDOOR_RG_NAME}/providers/"
        f"Microsoft.Cdn/checkEndpointNameAvailability?api-version={FRONTDOOR_API_VER}"
    )
    payload = json.dumps(
        {
            "name": endpoint,
            "type": FRONTDOOR_TYPE,
            "autoGeneratedDomainNameLabelScope": "TenantReuse",
        }
    )
    try:
        result = subprocess.run(
            [
                "az",
                "rest",
                "--method",
                "post",
                "--url",
                url,
                "--body",
                payload,
                "--query",
                "{available:nameAvailable,reason:reason,message:message}",
                "-o",
                "tsv",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        log_dbg(f"az rest failed for frontdoor check: {hostname}", debug)
        return ("", "az_failed", "az rest failed")
    if result.returncode != 0:
        log_dbg(f"az rest error for {hostname}: {result.stderr.strip()}", debug)
        return ("", "az_failed", "az rest error")
    line = result.stdout.strip()
    if not line:
        return ("", "az_empty", "empty az response")
    parts = line.split("\t", 2)
    available = parts[0] if len(parts) > 0 else ""
    reason = parts[1] if len(parts) > 1 else ""
    message = parts[2] if len(parts) > 2 else ""
    return (available, reason or "none", message or "none")


def print_header(deadcheck: bool, onlydead: bool) -> None:
    if deadcheck and onlydead:
        print(
            f"{'DOMAIN':<30} {'SUBDOMAIN':<45} {'VALUE':<45} {'LIVE':<6} "
            "PROTO REGISTERABLE FD_AVAILABLE FD_REASON FD_MESSAGE"
        )
        print(
            f"{'------':<30} {'---------':<45} {'-----':<45} {'----':<6} "
            "----- ------------ ------------ --------- ----------"
        )
    elif deadcheck:
        print(
            f"{'DOMAIN':<30} {'SUBDOMAIN':<45} {'VALUE':<45} {'LIVE':<6} "
            "PROTO FD_AVAILABLE FD_REASON FD_MESSAGE"
        )
        print(
            f"{'------':<30} {'---------':<45} {'-----':<45} {'----':<6} "
            "----- ------------ --------- ----------"
        )
    else:
        print(f"{'DOMAIN':<30} {'SUBDOMAIN':<45} VALUE FD_AVAILABLE FD_REASON FD_MESSAGE")
        print(f"{'------':<30} {'---------':<45} ----- ------------ --------- ----------")


def init_output_writer(args):
    if not args.out_file or args.out_format not in ("json", "csv"):
        return (None, None)
    if args.out_format == "csv":
        handle = open(args.out_file, "w", encoding="utf-8", newline="")
        writer = csv.writer(handle)
        if args.deadcheck and args.onlydead:
            writer.writerow(
                [
                    "domain",
                    "subdomain",
                    "value",
                    "live",
                    "proto",
                    "registerable",
                    "fd_available",
                    "fd_reason",
                    "fd_message",
                ]
            )
        elif args.deadcheck:
            writer.writerow(
                [
                    "domain",
                    "subdomain",
                    "value",
                    "live",
                    "proto",
                    "fd_available",
                    "fd_reason",
                    "fd_message",
                ]
            )
        else:
            writer.writerow(["domain", "subdomain", "value", "fd_available", "fd_reason", "fd_message"])
        handle.flush()

        def emit(item):
            if args.deadcheck and args.onlydead:
                writer.writerow(
                    [
                        item["domain"],
                        item["subdomain"],
                        item["value"],
                        item["live"],
                        item["proto"],
                        item["registerable"],
                        item["fd_available"],
                        item["fd_reason"],
                        item["fd_message"],
                    ]
                )
            elif args.deadcheck:
                writer.writerow(
                    [
                        item["domain"],
                        item["subdomain"],
                        item["value"],
                        item["live"],
                        item["proto"],
                        item["fd_available"],
                        item["fd_reason"],
                        item["fd_message"],
                    ]
                )
            else:
                writer.writerow(
                    [
                        item["domain"],
                        item["subdomain"],
                        item["value"],
                        item["fd_available"],
                        item["fd_reason"],
                        item["fd_message"],
                    ]
                )
            handle.flush()

        return (handle, emit)

    handle = open(args.out_file, "w", encoding="utf-8")
    close_str = "\n]\n"
    handle.write("[\n]\n")
    handle.flush()
    state = {"first": True, "pos": len("[\n")}

    def emit(item):
        payload = json.dumps(item, separators=(",", ":"))
        handle.seek(state["pos"])
        prefix = "" if state["first"] else ",\n"
        handle.write(f"{prefix}{payload}")
        handle.write(close_str)
        handle.flush()
        state["pos"] = handle.tell() - len(close_str)
        state["first"] = False

    return (handle, emit)


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
    if not os.path.isfile(args.fragments_file):
        log_err(f"Cannot read fragments file: {args.fragments_file}", args.debug)
        return 1

    if args.onlydead:
        args.deadcheck = True

    suffixes = load_suffixes(args.fragments_file)
    scope_suffixes = SCOPE_SUFFIXES.get(args.scope) if args.scope else ()
    dedupe = set()

    print_header(args.deadcheck, args.onlydead)

    out_handle, emit_output = init_output_writer(args)

    fd_sub_id = ""
    queried = set()
    try:
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
                    log_dbg(
                        f"Shodan API unauthorized; check API key. Skipping domain: {core}",
                        args.debug,
                    )
                else:
                    log_dbg(f"Skipping domain (unresolved): {core}", args.debug)
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
                if scope_suffixes:
                    host_for_scope = extract_hostname(value)
                    if not is_suffix_match(host_for_scope, scope_suffixes):
                        log_dbg(
                            f"Scope filter miss for {fqdn} -> {value} (scope {args.scope})",
                            args.debug,
                        )
                        continue
                if not is_suffix_match(value, suffixes):
                    log_dbg(f"No suffix match for {fqdn} -> {value}", args.debug)
                    continue
                log_dbg(f"Matched suffix for {fqdn} -> {value}", args.debug)
                key = f"{core}|{fqdn}|{value}"
                if key in dedupe:
                    continue
                dedupe.add(key)
                live_state, live_proto = ("", "")
                registerable = ""
                fd_available, fd_reason, fd_message = ("", "", "")
                if args.deadcheck:
                    live_state, live_proto = check_live(value, 10)
                    if args.onlydead and live_state == "dead":
                        registerable = check_registerable(value, args.debug)
                if args.onlydead and live_state != "dead":
                    continue
                host_for_fd = extract_hostname(value)
                if is_frontdoor_host(host_for_fd):
                    if not fd_sub_id:
                        fd_sub_id = get_frontdoor_subscription_id(args.debug)
                    fd_available, fd_reason, fd_message = check_frontdoor_availability(
                        host_for_fd, args.debug, fd_sub_id
                    )
                item = {
                    "domain": core,
                    "subdomain": fqdn,
                    "value": value,
                    "live": live_state,
                    "proto": live_proto,
                    "registerable": registerable,
                    "fd_available": fd_available,
                    "fd_reason": fd_reason,
                    "fd_message": fd_message,
                }
                if emit_output:
                    emit_output(item)
                if args.deadcheck and args.onlydead:
                    print(
                        f"{domain:<30} {fqdn:<45} {value:<45} {live_state:<6} "
                        f"{live_proto:<5} {registerable:<12} {fd_available:<12} "
                        f"{fd_reason:<9} {fd_message}"
                    )
                elif args.deadcheck:
                    print(
                        f"{domain:<30} {fqdn:<45} {value:<45} {live_state:<6} "
                        f"{live_proto:<5} {fd_available:<12} {fd_reason:<9} {fd_message}"
                    )
                else:
                    print(
                        f"{domain:<30} {fqdn:<45} {value:<45} {fd_available:<12} "
                        f"{fd_reason:<9} {fd_message}"
                    )
    finally:
        if out_handle:
            out_handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
