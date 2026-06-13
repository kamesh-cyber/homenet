"""Minimal pure-Python SNMP v1/v2c client (GETNEXT walk).

Why this exists: SNMP v2c is a plaintext, community-based protocol, so a small
ASN.1/BER encoder plus a UDP socket is enough to walk IF-MIB counters. That means
the SNMP feature works with no third-party packages and no native net-snmp tools
to install — it just works after `pip install -r requirements.txt`.

Scope: GETNEXT-based walk of a subtree, SNMP v1 and v2c. SNMPv3 (which needs
auth/priv crypto) is not handled here — use the net-snmp CLI for that.
"""

import socket

# ---------------------------------------------------------------- BER encoding
def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, value):
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(n):
    if n == 0:
        return _tlv(0x02, b"\x00")
    out = b""
    val = n
    while val:
        out = bytes([val & 0xFF]) + out
        val >>= 8
    if out[0] & 0x80:          # keep it positive
        out = b"\x00" + out
    return _tlv(0x02, out)


def _enc_octstr(s):
    if isinstance(s, str):
        s = s.encode()
    return _tlv(0x04, s)


def _enc_null():
    return _tlv(0x05, b"")


def _enc_oid(oid):
    parts = [int(x) for x in oid.strip(".").split(".") if x != ""]
    if len(parts) < 2:
        parts = [1, 3]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            stack = [p & 0x7F]
            p >>= 7
            while p:
                stack.append((p & 0x7F) | 0x80)
                p >>= 7
            body += bytes(reversed(stack))
    return _tlv(0x06, body)


# ---------------------------------------------------------------- BER decoding
def _parse_tlv(data, i):
    tag = data[i]; i += 1
    length = data[i]; i += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    return tag, data[i:i + length], i + length


def _decode_oid(value):
    if not value:
        return ""
    first = value[0]
    parts = [first // 40, first % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def _decode_uint(value):
    n = 0
    for b in value:
        n = (n << 8) | b
    return n


# --------------------------------------------------------------------- the walk
def walk(host, community, base_oid, version="2c", port=161,
         timeout=2.0, retries=1, max_rows=4000):
    """Walk the subtree under base_oid via repeated GETNEXT.

    Returns {index: value} where `index` is the OID remainder after base_oid
    (int when purely numeric, else the full OID string), and `value` is an int
    for numeric SNMP types or a str for OCTET STRING.
    """
    ver_byte = 0 if str(version).lower().lstrip("v") == "1" else 1
    base = base_oid.strip(".")
    base_parts = [int(x) for x in base.split(".") if x != ""]
    results = {}
    current = base
    req_id = 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        while len(results) < max_rows:
            varbind = _tlv(0x30, _enc_oid(current) + _enc_null())
            vblist = _tlv(0x30, varbind)
            pdu = _tlv(0xA1, _enc_int(req_id) + _enc_int(0) + _enc_int(0) + vblist)
            msg = _tlv(0x30, _enc_int(ver_byte) + _enc_octstr(community) + pdu)
            req_id += 1

            resp = None
            for _ in range(retries + 1):
                try:
                    sock.sendto(msg, (host, port))
                    resp, _addr = sock.recvfrom(65535)
                    break
                except socket.timeout:
                    continue
                except OSError:
                    return results
            if not resp:
                break

            try:
                _, body, _ = _parse_tlv(resp, 0)        # outer SEQUENCE
                i = 0
                _, _, i = _parse_tlv(body, i)           # version
                _, _, i = _parse_tlv(body, i)           # community
                _, pdu_body, _ = _parse_tlv(body, i)    # response PDU
                j = 0
                _, _, j = _parse_tlv(pdu_body, j)       # request-id
                _, errstat, j = _parse_tlv(pdu_body, j)  # error-status
                _, _, j = _parse_tlv(pdu_body, j)       # error-index
                if _decode_uint(errstat) != 0:
                    break
                _, vbl_body, _ = _parse_tlv(pdu_body, j)  # varbind list
            except Exception:
                break

            next_oid = None
            k = 0
            ended = False
            while k < len(vbl_body):
                _, vb, k = _parse_tlv(vbl_body, k)
                m = 0
                _, oid_bytes, m = _parse_tlv(vb, m)
                vtag, vbytes, m = _parse_tlv(vb, m)
                oid_str = _decode_oid(oid_bytes)
                if vtag in (0x80, 0x81, 0x82):          # noSuchObject/Instance/endOfMib
                    ended = True
                    break
                oid_parts = [int(x) for x in oid_str.split(".") if x != ""]
                if oid_parts[:len(base_parts)] != base_parts:
                    ended = True                        # left the subtree
                    break
                suffix = oid_str[len(base) + 1:] if oid_str.startswith(base + ".") else oid_str
                key = int(suffix) if suffix.isdigit() else suffix
                if vtag == 0x04:
                    try:
                        value = vbytes.decode("utf-8")
                    except Exception:
                        value = vbytes.decode("latin-1", "replace")
                elif vtag == 0x06:
                    value = _decode_oid(vbytes)
                else:
                    value = _decode_uint(vbytes)
                results[key] = value
                next_oid = oid_str

            if ended or next_oid is None or next_oid == current:
                break
            current = next_oid
    finally:
        sock.close()
    return results
