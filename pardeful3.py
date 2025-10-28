import socket, struct, time, threading
from collections import defaultdict
from scapy.all import DNS, DNSRR, DNSQR

# -------- Configuration --------
ENABLE_CACHE = True
UPSTREAM_TIMEOUT = 3.0
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
]

# -------- Global cache --------
cache_answers = defaultdict(list)
cache_ns = defaultdict(list)
cache_lock = threading.Lock()

import sys
sys.stdout.reconfigure(line_buffering=True)

# -------------------------------------------------------------------
# ----------------------- Utility + Logging --------------------------
# -------------------------------------------------------------------

def log(msg):
    """Timestamped colored debug print"""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def safe_decode(x):
    try:
        return x.decode() if isinstance(x, bytes) else str(x)
    except Exception:
        return str(x)

import struct

def set_txid_in_raw_response(raw_resp, txid):
    """Replace transaction ID in raw DNS response bytes."""
    if raw_resp is None or len(raw_resp) < 2:
        return raw_resp
    # TXID is first 2 bytes of DNS message
    return struct.pack(">H", txid & 0xFFFF) + raw_resp[2:]

from scapy.all import DNS, DNSRR

from scapy.all import DNS, DNSRR

def build_response_from_cache(query, answers):
    """
    Build a valid DNS response from cache entries.
    - 'answers' is a list of IP strings (A records).
    """
    resp = DNS(
        id=query.id,
        qr=1,   # response
        aa=1,   # authoritative
        ra=1,   # recursion available
        qd=query.qd
    )

    # Initialize 'an' properly
    answer_rrs = None
    for ip in answers:
        rr = DNSRR(rrname=query.qd.qname, type=query.qd.qtype, ttl=60, rdata=ip)
        if answer_rrs is None:
            answer_rrs = rr
        else:
            answer_rrs /= rr

    if answer_rrs:
        resp.an = answer_rrs
        resp.ancount = len(answers)

    return bytes(resp)

# -------------------------------------------------------------------
# ----------------------- Packet builders ----------------------------
# -------------------------------------------------------------------

def build_dns_query_raw(domain, qtype=1, rd=0, txid=0x1234):
    flags = 0x0100 if rd else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = b"".join(len(p).to_bytes(1, "big") + p.encode() for p in domain.split(".")) + b"\x00"
    qtype_qclass = struct.pack(">HH", qtype, 1)
    return header + qname + qtype_qclass


def query_upstream_raw(domain, server, qtype=1, rd=0, timeout=UPSTREAM_TIMEOUT):
    pkt = build_dns_query_raw(domain, qtype=qtype, rd=rd)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        log(f"[UPSTREAM]  {server}:53 for {domain} (type={qtype})")
        s.sendto(pkt, (server, 53))
        resp, _ = s.recvfrom(4096)
        log(f"[UPSTREAM]  Response {len(resp)} bytes from {server}")
        return resp
    except socket.timeout:
        log(f"[TIMEOUT] {server} for {domain}")
        return None
    except Exception as e:
        log(f"[ERROR] query_upstream_raw {server}: {e}")
        return None
    finally:
        s.close()


# -------------------------------------------------------------------
# ----------------------- Parsing helpers ----------------------------
# -------------------------------------------------------------------

def parse_with_scapy(raw_resp):
    if raw_resp is None:
        return [], [], {}, None, []

    try:
        dns_pkt = DNS(raw_resp)
    except Exception as e:
        log(f"[PARSE ERROR] {e}")
        return [], [], {}, None, []

    answers = []
    ns_names = []
    add_map = {}      # owner_name -> [ips]
    auth_zones = []

    # Answers
    for i in range(getattr(dns_pkt, "ancount", 0)):
        rr = dns_pkt.an[i]
        answers.append({
            "name": safe_decode(rr.rrname).rstrip("."),
            "type": int(rr.type),
            "rdata": rr.rdata,
            "ttl": int(rr.ttl)
        })

    # Authority (NS) -- collect NS rdata and owner(rrname) as zone(s)
    for i in range(getattr(dns_pkt, "nscount", 0)):
        rr = dns_pkt.ns[i]
        # rr.rdata is NS hostname, rr.rrname is the zone being referred
        ns_names.append(safe_decode(rr.rdata).rstrip("."))
        auth_zones.append(safe_decode(rr.rrname).rstrip("."))

    # Additional (A) -- build map owner -> list of IP(s)
    for i in range(getattr(dns_pkt, "arcount", 0)):
        rr = dns_pkt.ar[i]
        owner = safe_decode(rr.rrname).rstrip(".")
        if int(rr.type) == 1:  # A record
            add_map.setdefault(owner, []).append(str(rr.rdata))

    return answers, ns_names, add_map, dns_pkt, auth_zones
# -------------------------------------------------------------------
# ----------------------- Cache Management ---------------------------
# -------------------------------------------------------------------

# --- utilities (ensure these exist) ---
def _norm(name):
    """Normalize DNS names for cache keys (no trailing dot, lowercase)."""
    return name.strip().rstrip('.').lower()

# --- improved cache insert ---
def cache_insert_zone(zone, ns_list=None, ip_list=None, glue_map=None):
    """
    zone: delegated zone (e.g. 'google.com')
    ns_list: list of NS hostnames (strings, trailing dot optional)
    ip_list: list of IPs for the zone (answers)
    glue_map: dict mapping owner_name -> [ips] (from additional section)
    """
    if not ENABLE_CACHE:
        return

    zone = zone.strip('.').lower()
    with cache_lock:
        if ns_list:
            ns_list_norm = [n.strip('.').lower() for n in ns_list]
            old_ns = cache_ns.get(zone, [])
            cache_ns[zone] = list(set(old_ns + ns_list_norm))
            log(f"[CACHE+NS] {zone} -> {cache_ns[zone]}")

        if ip_list:
            old_ips = cache_answers.get(zone, [])
            cache_answers[zone] = list(set(old_ips + [str(x) for x in ip_list]))
            log(f"[CACHE+IP] {zone} -> {cache_answers[zone]}")

        # If glue_map present, map glue owner -> its IPs
        if glue_map:
            for owner, ips in glue_map.items():
                owner_n = owner.strip('.').lower()
                old = cache_answers.get(owner_n, [])
                cache_answers[owner_n] = list(set(old + [str(x) for x in ips]))
                log(f"[CACHE+GLUE] {owner_n} -> {cache_answers[owner_n]}")

        # Propagate minimal parent existence so hierarchical lookup can find TLD/parent
        parts = zone.split('.')
        if len(parts) > 1:
            parent = '.'.join(parts[1:])
            cache_ns.setdefault(parent, cache_ns.get(parent, []))
            cache_answers.setdefault(parent, cache_answers.get(parent, []))


def get_cached_ips(zone):
    """Return IPs for a given zone or its parent zones."""
    zone = zone.strip('.').lower()
    with cache_lock:
        parts = zone.split('.')
        for i in range(len(parts)):
            sub = '.'.join(parts[i:])
            if sub in cache_answers:
                return cache_answers[sub]
    return []


def get_cached_ns(zone):
    """Return NS for a given zone or its parent zones."""
    zone = zone.strip('.').lower()
    with cache_lock:
        parts = zone.split('.')
        for i in range(len(parts)):
            sub = '.'.join(parts[i:])
            if sub in cache_ns:
                return cache_ns[sub]
    return []

def get_best_cached_ns_or_ips(domain):
    domain = domain.strip('.').lower()
    # 1) exact IPs for domain
    ips = get_cached_ips(domain)
    if ips:
        return ips

    # 2) ns list for domain -> try to resolve ns -> ips
    ns_list = get_cached_ns(domain)
    if ns_list:
        all_ips = []
        for ns in ns_list:
            all_ips.extend(get_cached_ips(ns))
        if all_ips:
            return list(set(all_ips))

    # 3) walk up parents: google.com -> com
    parts = domain.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        ips = get_cached_ips(parent)
        if ips:
            return ips
        ns_list = get_cached_ns(parent)
        if ns_list:
            all_ips = []
            for ns in ns_list:
                all_ips.extend(get_cached_ips(ns))
            if all_ips:
                return list(set(all_ips))

    return None

def cache_lookup_answer(qname, qtype=1):
    """Return cached A or AAAA answers for a fully qualified name."""
    with cache_lock:
        # Try exact domain match
        if qname in cache_answers:
            return cache_answers[qname]
        # Try parent zone fallback (for e.g., www.google.com → google.com)
        labels = qname.split('.')
        for i in range(1, len(labels)):
            zone = '.'.join(labels[i:])
            if zone in cache_answers:
                return cache_answers[zone]
        return []


# -------------------------------------------------------------------
# ----------------------- DFS Iterative Resolver ---------------------
# -------------------------------------------------------------------
def resolve_iterative(domain, qtype=1, max_depth=10,type=0):
    log(f"[ITER] Start DFS resolution for {domain}")
    domain = domain.rstrip(".").lower()
    labels = domain.split(".")
    path = [".".join(labels[i:]) for i in range(len(labels))] + ["."]

    # Try to start from best cached servers (TLD or authoritative)
    best = get_best_cached_ns_or_ips(domain)
    if best:
        ns_ips = best[:]  # copy
        current_zone = domain
        log(f"[CACHE START] Using cached servers for {domain}: {ns_ips}")
    else:
        ns_ips = list(ROOT_SERVERS)  # keep as a list of IP strings
        current_zone = "."
    for depth in range(max_depth):
        log(f"[DFS@{depth}] Zone={current_zone}, Servers={ns_ips}")
        answered = False

        for server in ns_ips:
            raw = query_upstream_raw(domain, server, qtype=qtype, rd=type)
            if raw is None:
                continue

            answers, ns_names, add_map, dns_pkt, auth_zones = parse_with_scapy(raw)

            # Final answer?
            if answers:
                a_ips = [a["rdata"] for a in answers if a["type"] == 1]
                if a_ips:
                    # cache the answer for the queried name
                    cache_insert_zone(domain, None, a_ips, None)
                    log(f"[ANSWER] {domain} -> {a_ips}")
                    return raw

            # Delegation/referral?
            if ns_names:
                # determine delegated zone: prefer the authority owner name if present
                if auth_zones:
                    next_zone = auth_zones[0].strip('.').lower()
                else:
                    # fallback — choose shortest ns name minus its host label (best-effort)
                    next_zone = '.'.join(ns_names[0].split('.')[-2:]).strip('.').lower()

                # glue_map: use add_map to map owner -> ips
                # Note: add_map keys are owner names from additional section (could be NS names)
                glue_map = {}
                # For each ns_name, see if add_map contains that ns as owner
                ns_norm = [n.strip('.').lower() for n in ns_names]
                for ns in ns_norm:
                    ips = add_map.get(ns, []) or add_map.get(ns + '.', [])
                    if ips:
                        glue_map[ns] = ips

                # Cache delegation: next_zone -> ns list, and store glue_map so ns->ips are cached
                cache_insert_zone(next_zone, ns_norm, None, glue_map if glue_map else None)

                # Determine next ns_ips to query:
                # 1) prefer glue_map IPs
                next_ips = []
                for ips in glue_map.values():
                    next_ips.extend(ips)

                # 2) if no glue, try cached IPs for each ns host
                if not next_ips:
                    for ns in ns_norm:
                        next_ips.extend(get_cached_ips(ns))

                next_ips = list(set(next_ips))

                if not next_ips:
                    log(f"[REFERRAL] {next_zone} gave NS but no glue and no cached IPs - continuing to other servers")
                    # try other server in current ns_ips loop
                    continue

                log(f"[DELEGATION] {current_zone} -> {next_zone} via {next_ips}")
                current_zone = next_zone
                ns_ips = next_ips
                answered = True
                break  # go one level deeper

        if not answered:
            log(f"[DFS-END] No delegation or final answer for {domain}")
            return None

    log(f"[DFS-FAIL] Max depth reached for {domain}")
    return None



# -------------------------------------------------------------------
# ----------------------- Query Handler ------------------------------
# -------------------------------------------------------------------

def handle_query(data, addr, sock):
    try:
        query = DNS(data)
    except Exception as e:
        log(f"[PARSE FAIL] {e}")
        return
    if query.qdcount < 1:
        return
    qname = safe_decode(query.qd.qname).rstrip(".")
    qtype = int(query.qd.qtype)
    rd_flag = int(query.rd)
    txid = int(query.id)
    log(f"[REQ] {addr} {qname} type={qtype} RD={rd_flag}")
    
    
    # ---------------- RECURSIVE MODE ---------------- #
    if rd_flag == 1:
        # First, check cache directly
        cached = cache_lookup_answer(qname, qtype)
        if cached:
            resp = build_response_from_cache(query, cached)
            sock.sendto(resp, addr)
            log(f"[CACHE HIT] {qname}")
            return

        # Try to resolve using DFS path (. → .com → google.com → www.google.com)
        raw = resolve_iterative(qname, qtype=qtype,type=1)
        if raw:
            # Update transaction ID and send back
            resp = set_txid_in_raw_response(raw, txid)
            sock.sendto(resp, addr)
            log(f"[RESOLVED DFS] {qname}")
            return
        else:
            # SERVFAIL if resolution fails
            sock.sendto(bytes(DNS(id=txid, qr=1, ra=1, rcode=2, qd=query.qd)), addr)
            log(f"[SERVFAIL] {qname}")
            return

    # ---------------- ITERATIVE MODE ---------------- #
    else:
        cached = cache_lookup_answer(qname, qtype)
        if cached:
            sock.sendto(build_response_from_cache(query, cached), addr)
            log(f"[CACHE HIT ITER] {qname}")
            return

        # Iterative mode should follow one full chain once (like a recursive step)
        # but stop at referral instead of continuing.
        referral_resp = resolve_iterative(qname, qtype=qtype,type=0)
        if referral_resp:
            resp = set_txid_in_raw_response(referral_resp, txid)
            sock.sendto(resp, addr)
            log(f"[ITERATIVE REFERRAL] {qname}")
            return

        sock.sendto(bytes(DNS(id=txid, qr=1, ra=1, rcode=2, qd=query.qd)), addr)
        log(f"[ITERATIVE FAIL] {qname}")


# -------------------------------------------------------------------
# ----------------------- Main Server Loop ---------------------------
# -------------------------------------------------------------------

LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53           

def serve_forever(sock):
    """Run the server loop for a few queries (non-threaded)"""
    print(f"DNS server listening on {LISTEN_ADDR}:{LISTEN_PORT} (ENABLE_CACHE={ENABLE_CACHE})")
    try:
        while(True):  # just handle 5 queries and exit
            data, addr = sock.recvfrom(4096)
            handle_query(data, addr, sock)
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        sock.close()


def send_test_query(domain, qtype=1):
    """Send a DNS query to the local server"""
    pkt = DNS(id=0x1000 + qtype, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(pkt), (LISTEN_ADDR, LISTEN_PORT))
    sock.close()
    print(f"[CLIENT] Sent query for {domain} (qtype={qtype})")


if __name__ == "__main__":
    # --- Start server socket ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))

    print("\n[INFO] === Starting single-threaded DNS server ===")
    # Run the server loop to receive and process them
    serve_forever(sock)