#!/usr/bin/env python3
"""
ns_to_skudonet.py
=================
Converts Citrix ADC (NetScaler) ns.conf configuration to Skudonet (ZEVENET)
load balancer configuration.

Produces two output files:
  skudonet_config.json  - Structured JSON of all farms, services, backends,
                          certificates, and health checks.
  skudonet_apply.sh     - curl-based shell script using Skudonet ZAPI v4.0
                          REST API endpoints.

NOTE: VLAN configuration and floating IPs are intentionally skipped as those
are assumed to have been handled separately.

Usage:
  python ns_to_skudonet.py ns.conf [--output-dir ./output] [--dry-run] [-v]

Author : ns_to_skudonet migration tool
Version: 1.0.0
Python : 3.6+  (no external dependencies)
"""

from __future__ import annotations

import argparse
import json
import os
import textwrap
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


###############################################################################
# SECTION 1 – DATA MODEL DATACLASSES
###############################################################################

@dataclass
class NSServer:
    """
    Represents an 'add server' entry.
    NetScaler uses logical server names that map to IP addresses.
    These become backend IP addresses in Skudonet.
    """
    name: str
    ip: str
    state: str = "ENABLED"
    comment: str = ""


@dataclass
class NSMonitor:
    """
    Represents an 'add lb monitor' entry.
    Maps to Skudonet FarmGuardian health check configuration.

    Monitor type translation:
      HTTP / HTTP-ECV  -> check_http (Nagios-style)
      TCP  / TCP-ECV   -> check_tcp
      PING / ICMP      -> check_ping
      Custom           -> check_tcp with a manual review note
    """
    name: str
    type: str                          # HTTP, TCP, PING, HTTP-ECV, TCP-ECV, …
    interval: int = 5
    response_timeout: int = 2
    retries: int = 3
    down_time: int = 30
    send: str = ""                     # ECV send string / HTTP request body
    recv: str = ""                     # ECV expected response substring
    http_request: str = ""             # HTTP monitor: 'GET /path HTTP/1.0'
    custom_headers: Dict[str, str] = field(default_factory=dict)
    dest_port: int = 0
    dest_ip: str = ""
    state: str = "ENABLED"
    raw_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class NSServiceGroup:
    """
    Represents an 'add serviceGroup' entry plus all its bound members.

    A serviceGroup is a pool of backend servers in NetScaler.
    In Skudonet this becomes:
      - HTTP profile  -> a Service containing one or more Backends
      - L4xNAT profile -> Backends directly attached to the Farm
    """
    name: str
    protocol: str          # HTTP, HTTPS, TCP, UDP, SSL, SSL_TCP, …
    state: str = "ENABLED"
    max_client: int = 0
    max_req: int = 0
    use_source_ip: bool = False
    # Each member: (server_name_or_ip, port, weight)
    members: List[Tuple[str, int, int]] = field(default_factory=list)
    monitors: List[str] = field(default_factory=list)
    comment: str = ""


@dataclass
class NSService:
    """
    Represents an 'add service' entry (single server ↔ port pairing).
    Simpler than serviceGroup; becomes a single Backend in Skudonet.
    """
    name: str
    server: str            # server name or IP
    protocol: str
    port: int
    state: str = "ENABLED"
    max_client: int = 0
    monitors: List[str] = field(default_factory=list)
    comment: str = ""


@dataclass
class NSPersistence:
    """
    Persistence / session-affinity settings attached to a vserver.

    Skudonet persistence modes:
      HTTP  profile: IP | COOKIE | none
      L4xNAT profile: ip | none
    """
    type: str = ""         # SOURCEIP, COOKIEINSERT, SSLSESSIONID, RULE, NONE …
    timeout: int = 0       # seconds
    cookie_name: str = ""
    backup_persistence: str = ""


@dataclass
class NSSSLConfig:
    """
    SSL settings for a vserver collected from:
      - bind ssl vserver
      - set  ssl vserver
    """
    cert_key_names: List[str] = field(default_factory=list)  # primary certs
    sni_certs: List[str] = field(default_factory=list)        # SNI certs
    cipher_alias: str = ""
    ssl_profile: str = ""
    ssl_protocols: List[str] = field(default_factory=list)    # TLSv1.2, etc.
    client_auth: str = ""                                     # ENABLED/DISABLED


@dataclass
class NSVServer:
    """
    Represents either an 'add lb vserver' or 'add cs vserver' entry.
    This is the central object around which a Skudonet Farm is built.

    vs_type: "lb" = load-balancing vserver (direct → one Farm)
             "cs" = content-switching vserver (→ Farm with multiple Services)
    """
    name: str
    vs_type: str           # "lb" | "cs"
    protocol: str          # HTTP, HTTPS, TCP, UDP, SSL, ANY, …
    ip: str
    port: int
    lb_method: str = "ROUNDROBIN"
    persistence: NSPersistence = field(default_factory=NSPersistence)
    state: str = "ENABLED"
    timeout: int = 0
    down_state_flush: str = ""
    backup_vserver: str = ""

    # Bound resources
    service_groups: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

    # CS-specific: sorted list of (priority, policy_name, action_name)
    cs_bindings: List[Tuple[int, str, str]] = field(default_factory=list)
    default_cs_action: str = ""        # default target LB VS for CS

    ssl: NSSSLConfig = field(default_factory=NSSSLConfig)
    comment: str = ""


@dataclass
class NSCSPolicy:
    """
    Represents an 'add cs policy' entry.
    The rule expression (PIXL / classic) will be parsed to extract
    URL path and hostname patterns for Skudonet Service matching.
    """
    name: str
    rule: str = ""         # e.g. HTTP.REQ.URL.STARTSWITH("/api")
    action: str = ""       # associated cs action name


@dataclass
class NSCSAction:
    """
    Represents an 'add cs action' entry.
    Specifies the target LB vserver for matched CS traffic.
    """
    name: str
    target_lb: str = ""    # -targetLBVserver or -targetVserver


@dataclass
class NSResponderPolicy:
    """Represents an 'add responder policy' entry."""
    name: str
    rule: str = ""
    action: str = ""
    goto: str = ""         # NEXT / END


@dataclass
class NSResponderAction:
    """
    Represents an 'add responder action' entry.

    Common types:
      redirect        → Skudonet HTTP redirect
      respondwith     → custom response (manual review)
      noop            → no-op (skip)
    """
    name: str
    action_type: str = ""  # redirect, respondwith, noop, sqlinjection_check
    target: str = ""       # redirect URL or expression


@dataclass
class NSRewritePolicy:
    """Represents an 'add rewrite policy' entry."""
    name: str
    rule: str = ""
    action: str = ""
    goto: str = ""


@dataclass
class NSRewriteAction:
    """
    Represents an 'add rewrite action' entry.

    Common types:
      replace              → replace header value / URL
      insert_http_header   → add request header
      delete_http_header   → remove request header
      replace_http_res     → replace response header
      insert_http_req_header → add to request
    """
    name: str
    action_type: str = ""
    target: str = ""           # header name or URL path
    string_builder: str = ""   # -stringBuilderExpr value


@dataclass
class NSSSLCertKey:
    """
    Represents an 'add ssl certKey' entry.
    Maps to a certificate uploaded to Skudonet.
    """
    name: str
    cert_file: str = ""
    key_file: str = ""
    cert_type: str = "SERVER"   # SERVER or CLIENT
    linked_cert: str = ""       # chain cert from 'link ssl certKey'


###############################################################################
# SECTION 2 – NSConfigParser
###############################################################################

class NSConfigParser:
    """
    Parses a NetScaler ns.conf file into a flat list of
    (verb, [token, token, …]) tuples.

    Handles:
      - Line comments starting with '#'
      - Inline comments (# outside of quotes)
      - Line continuations with trailing backslash
      - Single-quoted and double-quoted strings (preserves spaces inside quotes)
      - Blank lines and whitespace-only lines
    """

    # Tokeniser: quoted strings or non-whitespace runs
    _TOKEN_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|[^\s]+""")

    def __init__(self, filepath: str):
        self.filepath  = filepath
        self.commands: List[Tuple[str, List[str]]] = []
        self._raw_line_count = 0

    # ------------------------------------------------------------------
    def load_and_parse(self) -> "NSConfigParser":
        """Read the file, handle continuations, tokenise every command line."""
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()

        self._raw_line_count = len(raw_lines)

        # Stitch continuation lines together
        joined: List[str] = []
        buf = ""
        for line in raw_lines:
            stripped = line.rstrip("\r\n")
            if stripped.endswith("\\"):
                buf += stripped[:-1] + " "
            else:
                buf += stripped
                joined.append(buf)
                buf = ""
        if buf:
            joined.append(buf)

        # Parse each logical line
        for line in joined:
            clean = self._strip_comment(line).strip()
            if not clean:
                continue
            tokens = self._TOKEN_RE.findall(clean)
            tokens = [self._unquote(t) for t in tokens]
            if tokens:
                self.commands.append((tokens[0], tokens[1:]))

        return self

    # ------------------------------------------------------------------
    @staticmethod
    def _strip_comment(line: str) -> str:
        """Remove the # … comment from a line, respecting quoted sections."""
        result: List[str] = []
        in_single = False
        in_double = False
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                # handle escaped quote inside double quotes
                if in_double and i > 0 and line[i - 1] == "\\":
                    pass  # escaped – stay in double-quote mode
                else:
                    in_double = not in_double
            elif ch == '#' and not in_single and not in_double:
                break
            result.append(ch)
            i += 1
        return "".join(result)

    @staticmethod
    def _unquote(token: str) -> str:
        """Strip surrounding single or double quotes from a token."""
        if len(token) >= 2:
            if (token[0] == "'" and token[-1] == "'") or \
               (token[0] == '"' and token[-1] == '"'):
                # Also unescape \" inside double-quoted strings
                inner = token[1:-1]
                if token[0] == '"':
                    inner = inner.replace('\\"', '"')
                return inner
        return token


###############################################################################
# SECTION 3 – NetScalerModel
###############################################################################

class NetScalerModel:
    """
    Builds a typed in-memory model of the entire NetScaler configuration by
    iterating over the (verb, args) command list from NSConfigParser.

    All entity dictionaries are keyed by entity name (case-sensitive, matching
    NetScaler's own case sensitivity).

    Skipped intentionally:
      - VLAN configuration (add vlan, bind vlan)
      - Floating IP / SNIP configuration (add ns ip -type SNIP/VIP VLAN)
      - HA/cluster configuration
      - GSLB (noted but not deeply modelled)
      - Audit / syslog configuration
    """

    def __init__(self):
        self.servers:            Dict[str, NSServer]          = {}
        self.service_groups:     Dict[str, NSServiceGroup]    = {}
        self.services:           Dict[str, NSService]         = {}
        self.lb_vservers:        Dict[str, NSVServer]         = {}
        self.cs_vservers:        Dict[str, NSVServer]         = {}
        self.monitors:           Dict[str, NSMonitor]         = {}
        self.ssl_certkeys:       Dict[str, NSSSLCertKey]      = {}
        self.cs_policies:        Dict[str, NSCSPolicy]        = {}
        self.cs_actions:         Dict[str, NSCSAction]        = {}
        self.responder_policies: Dict[str, NSResponderPolicy] = {}
        self.responder_actions:  Dict[str, NSResponderAction] = {}
        self.rewrite_policies:   Dict[str, NSRewritePolicy]   = {}
        self.rewrite_actions:    Dict[str, NSRewriteAction]   = {}

        # { vserver_name: [(policy_name, priority, bind_point), …] }
        self.vserver_responder_bindings: Dict[str, List] = defaultdict(list)
        self.vserver_rewrite_bindings:   Dict[str, List] = defaultdict(list)

        # Global timeout settings from 'set ns timeout'
        self.ns_timeout: Dict[str, int] = {}

        # Raw commands that were not handled – reported in summary
        self.unhandled: List[str] = []

    # ------------------------------------------------------------------
    def build(self, commands: List[Tuple[str, List[str]]]) -> "NetScalerModel":
        """Dispatch every command to the appropriate handler."""
        for verb, args in commands:
            if not args:
                continue
            try:
                self._dispatch(verb.lower(), args)
            except Exception as exc:                             # noqa: BLE001
                self.unhandled.append(
                    f"PARSE_ERROR '{verb} {' '.join(args)}': {exc}"
                )
        return self

    # ------------------------------------------------------------------
    # Central dispatcher
    # ------------------------------------------------------------------

    def _dispatch(self, verb: str, args: List[str]):
        """Route a command to the right handler based on verb + noun(s)."""
        noun = args[0].lower() if args else ""
        sub  = args[1].lower() if len(args) > 1 else ""
        rest = args[2:]           # everything after 'verb noun sub'

        if verb == "add":
            if noun == "server":
                self._add_server(args[1:])
            elif noun == "servicegroup":
                self._add_servicegroup(args[1:])
            elif noun == "service" and sub not in ("group",):
                self._add_service(args[1:])
            elif noun == "lb" and sub == "vserver":
                self._add_lb_vserver(rest)
            elif noun == "lb" and sub == "monitor":
                self._add_lb_monitor(rest)
            elif noun == "cs" and sub == "vserver":
                self._add_cs_vserver(rest)
            elif noun == "cs" and sub == "policy":
                self._add_cs_policy(rest)
            elif noun == "cs" and sub == "action":
                self._add_cs_action(rest)
            elif noun == "ssl" and sub == "certkey":
                self._add_ssl_certkey(rest)
            elif noun == "responder" and sub == "policy":
                self._add_responder_policy(rest)
            elif noun == "responder" and sub == "action":
                self._add_responder_action(rest)
            elif noun == "rewrite" and sub == "policy":
                self._add_rewrite_policy(rest)
            elif noun == "rewrite" and sub == "action":
                self._add_rewrite_action(rest)
            else:
                self.unhandled.append(f"add {' '.join(args)}")

        elif verb == "bind":
            if noun == "lb" and sub == "vserver":
                self._bind_lb_vserver(rest)
            elif noun == "lb" and sub == "monitor":
                self._bind_lb_monitor(rest)
            elif noun == "servicegroup":
                self._bind_servicegroup(args[1:])
            elif noun == "cs" and sub == "vserver":
                self._bind_cs_vserver(rest)
            elif noun == "ssl" and sub == "vserver":
                self._bind_ssl_vserver(rest)
            else:
                self.unhandled.append(f"bind {' '.join(args)}")

        elif verb == "set":
            if noun == "ns" and sub == "timeout":
                self._set_ns_timeout(rest)
            elif noun == "ssl" and sub == "vserver":
                self._set_ssl_vserver(rest)
            else:
                self.unhandled.append(f"set {' '.join(args)}")

        elif verb == "link":
            if noun == "ssl" and sub == "certkey":
                self._link_ssl_certkey(rest)
            else:
                self.unhandled.append(f"link {' '.join(args)}")

        elif verb in {
            # Silently skip commands that do not affect the migration output
            "enable", "disable", "save", "show", "stat", "rm", "unset",
            "clear", "exit", "quit", "done", "apply", "sync",
        }:
            pass

        else:
            self.unhandled.append(f"{verb} {' '.join(args)}")

    # ------------------------------------------------------------------
    # Flag / positional argument parser
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_flags(tokens: List[str]) -> Dict[str, str]:
        """
        Parse a flat token list into a dict.

        Examples:
          ['-state', 'ENABLED', '-timeout', '30']
          -> {'-state': 'ENABLED', '-timeout': '30'}

          ['myName', '10.0.0.1', '-state', 'ENABLED']
          -> {'_pos0': 'myName', '_pos1': '10.0.0.1', '-state': 'ENABLED'}
        """
        result: Dict[str, str] = {}
        pos = 0
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t.startswith("-") and not re.match(r"^-\d+(\.\d+)?$", t):
                # It's a flag name
                key = t.lower()
                # Look ahead for the value
                if i + 1 < len(tokens):
                    nxt = tokens[i + 1]
                    # If next token is also a flag name, treat current as boolean
                    if nxt.startswith("-") and not re.match(r"^-\d+(\.\d+)?$", nxt):
                        result[key] = "true"
                    else:
                        result[key] = nxt
                        i += 1
                else:
                    result[key] = "true"
            else:
                result[f"_pos{pos}"] = t
                pos += 1
            i += 1
        return result

    def _resolve_ip(self, name_or_ip: str) -> str:
        """Resolve a server name to an IP, or return the value as-is."""
        if name_or_ip in self.servers:
            return self.servers[name_or_ip].ip
        return name_or_ip

    def _get_vserver(self, name: str) -> Optional[NSVServer]:
        """Return an lb or cs vserver by name, or None."""
        return self.lb_vservers.get(name) or self.cs_vservers.get(name)

    # ------------------------------------------------------------------
    # ADD handlers
    # ------------------------------------------------------------------

    def _add_server(self, args: List[str]):
        """
        add server <name> <ip> [-state ENABLED|DISABLED] [-comment "…"]
        """
        flags   = self._parse_flags(args)
        name    = flags.get("_pos0", "")
        ip      = flags.get("_pos1", "")
        state   = flags.get("-state", "ENABLED").upper()
        comment = flags.get("-comment", "")
        if name and ip:
            self.servers[name] = NSServer(
                name=name, ip=ip, state=state, comment=comment
            )

    def _add_servicegroup(self, args: List[str]):
        """
        add serviceGroup <name> <protocol>
            [-state ENABLED|DISABLED]
            [-maxClient <n>] [-maxReq <n>]
            [-useSourceIP YES|NO]
            [-comment "…"]
        """
        flags      = self._parse_flags(args)
        name       = flags.get("_pos0", "")
        protocol   = flags.get("_pos1", "TCP").upper()
        state      = flags.get("-state", "ENABLED").upper()
        max_client = int(flags.get("-maxclient", 0) or 0)
        max_req    = int(flags.get("-maxreq", 0) or 0)
        use_sip    = flags.get("-usesourceip", "no").lower() in ("yes", "true", "enabled")
        comment    = flags.get("-comment", "")
        if name:
            self.service_groups[name] = NSServiceGroup(
                name=name, protocol=protocol, state=state,
                max_client=max_client, max_req=max_req,
                use_source_ip=use_sip, comment=comment,
            )

    def _add_service(self, args: List[str]):
        """
        add service <name> <server> <protocol> <port>
            [-state ENABLED|DISABLED]
            [-maxClient <n>]
            [-monitorName <mon>]
        """
        flags      = self._parse_flags(args)
        name       = flags.get("_pos0", "")
        server     = flags.get("_pos1", "")
        protocol   = flags.get("_pos2", "TCP").upper()
        port_s     = flags.get("_pos3", "80")
        try:
            port   = int(port_s)
        except ValueError:
            port   = 80
        state      = flags.get("-state", "ENABLED").upper()
        max_client = int(flags.get("-maxclient", 0) or 0)
        mon_name   = flags.get("-monitorname", "")
        if name:
            svc = NSService(
                name=name, server=server, protocol=protocol,
                port=port, state=state, max_client=max_client,
            )
            if mon_name:
                svc.monitors.append(mon_name)
            self.services[name] = svc

    def _add_lb_vserver(self, args: List[str]):
        """
        add lb vserver <name> <protocol> <ip> <port>
            [-lbMethod <method>]
            [-persistenceType <type>]
            [-persistenceTimeout | -timeout <n>]
            [-cookieName <name>]
            [-state ENABLED|DISABLED]
            [-timeout <n>]
            [-backupVServer <name>]
            [-comment "…"]
        """
        flags    = self._parse_flags(args)
        name     = flags.get("_pos0", "")
        proto    = flags.get("_pos1", "TCP").upper()
        ip       = flags.get("_pos2", "0.0.0.0")
        port_s   = flags.get("_pos3", "0")
        try:
            port = int(port_s)
        except ValueError:
            port = 0
        lb_meth  = flags.get("-lbmethod", "ROUNDROBIN").upper()
        state    = flags.get("-state", "ENABLED").upper()
        timeout  = int(flags.get("-timeout", 0) or 0)
        backup   = flags.get("-backupvserver", "")
        comment  = flags.get("-comment", "")

        # Persistence
        pers_type = flags.get("-persistencetype", "").upper()
        pers_to   = int(
            flags.get("-persistencetimeout",
                      flags.get("-timeout", 0) or 0) or 0
        )
        cookie_name = flags.get("-cookiename", "")
        pers = NSPersistence(
            type=pers_type, timeout=pers_to, cookie_name=cookie_name
        )

        if name:
            self.lb_vservers[name] = NSVServer(
                name=name, vs_type="lb", protocol=proto,
                ip=ip, port=port, lb_method=lb_meth,
                persistence=pers, state=state, timeout=timeout,
                backup_vserver=backup, comment=comment,
            )

    def _add_cs_vserver(self, args: List[str]):
        """
        add cs vserver <name> <protocol> <ip> <port>
            [-lbMethod <method>]
            [-persistenceType <type>]
            [-state ENABLED|DISABLED]
            [-comment "…"]
        """
        flags   = self._parse_flags(args)
        name    = flags.get("_pos0", "")
        proto   = flags.get("_pos1", "HTTP").upper()
        ip      = flags.get("_pos2", "0.0.0.0")
        port_s  = flags.get("_pos3", "80")
        try:
            port = int(port_s)
        except ValueError:
            port = 80
        state   = flags.get("-state", "ENABLED").upper()
        lb_meth = flags.get("-lbmethod", "ROUNDROBIN").upper()
        comment = flags.get("-comment", "")

        pers_type   = flags.get("-persistencetype", "").upper()
        pers_to     = int(flags.get("-persistencetimeout", 0) or 0)
        cookie_name = flags.get("-cookiename", "")
        pers = NSPersistence(
            type=pers_type, timeout=pers_to, cookie_name=cookie_name
        )

        if name:
            self.cs_vservers[name] = NSVServer(
                name=name, vs_type="cs", protocol=proto,
                ip=ip, port=port, lb_method=lb_meth,
                persistence=pers, state=state, comment=comment,
            )

    def _add_lb_monitor(self, args: List[str]):
        """
        add lb monitor <name> <type>
            [-interval <n>]   [-resTimeout <n>]  [-retries <n>]
            [-downTime <n>]
            [-send <str>]     [-recv <str>]
            [-httpRequest <str>]
            [-destPort <n>]   [-destIP <ip>]
            [-state ENABLED|DISABLED]
        """
        flags   = self._parse_flags(args)
        name    = flags.get("_pos0", "")
        mtype   = flags.get("_pos1", "TCP").upper()
        if not name:
            return

        mon = NSMonitor(
            name             = name,
            type             = mtype,
            interval         = int(flags.get("-interval", 5) or 5),
            response_timeout = int(flags.get("-restimeout", 2) or 2),
            retries          = int(flags.get("-retries", 3) or 3),
            down_time        = int(flags.get("-downtime", 30) or 30),
            send             = flags.get("-send", ""),
            recv             = flags.get("-recv", ""),
            http_request     = flags.get("-httprequest", ""),
            dest_port        = int(flags.get("-destport", 0) or 0),
            dest_ip          = flags.get("-destip", ""),
            state            = flags.get("-state", "ENABLED").upper(),
        )
        mon.raw_params = {k: v for k, v in flags.items() if not k.startswith("_pos")}
        self.monitors[name] = mon

    def _add_ssl_certkey(self, args: List[str]):
        """
        add ssl certKey <name>
            -cert <file>
            [-key <file>]
            [-certType SERVER|CLIENT]
        """
        flags = self._parse_flags(args)
        name  = flags.get("_pos0", "")
        cert  = flags.get("-cert", "")
        key   = flags.get("-key", "")
        ctype = flags.get("-certtype", "SERVER").upper()
        if name:
            self.ssl_certkeys[name] = NSSSLCertKey(
                name=name, cert_file=cert, key_file=key, cert_type=ctype,
            )

    def _add_cs_policy(self, args: List[str]):
        """
        add cs policy <name> -rule <expression> [-action <cs_action_name>]
        """
        flags  = self._parse_flags(args)
        name   = flags.get("_pos0", "")
        rule   = flags.get("-rule", "")
        action = flags.get("-action", "")
        if name:
            self.cs_policies[name] = NSCSPolicy(
                name=name, rule=rule, action=action
            )

    def _add_cs_action(self, args: List[str]):
        """
        add cs action <name>
            -targetLBVserver <lb_vserver> | -targetVserver <vserver>
        """
        flags      = self._parse_flags(args)
        name       = flags.get("_pos0", "")
        target_lb  = flags.get(
            "-targetlbvserver",
            flags.get("-targetvserver", "")
        )
        if name:
            self.cs_actions[name] = NSCSAction(
                name=name, target_lb=target_lb
            )

    def _add_responder_policy(self, args: List[str]):
        """
        add responder policy <name> <rule_expression> <action>
        OR
        add responder policy <name> -rule <expression> -action <action>
        """
        flags  = self._parse_flags(args)
        name   = flags.get("_pos0", "")
        # Support both positional and flag-style
        rule   = flags.get("-rule", flags.get("_pos1", ""))
        action = flags.get("-action", flags.get("_pos2", ""))
        goto   = flags.get("-goto", "")
        if name:
            self.responder_policies[name] = NSResponderPolicy(
                name=name, rule=rule, action=action, goto=goto
            )

    def _add_responder_action(self, args: List[str]):
        """
        add responder action <name> <type> <target>
        Types: redirect, respondwith, noop, respondwithhtmlpage, …
        """
        flags  = self._parse_flags(args)
        name   = flags.get("_pos0", "")
        atype  = flags.get("_pos1", "")
        target = flags.get("_pos2", flags.get("-target", ""))
        if name:
            self.responder_actions[name] = NSResponderAction(
                name=name, action_type=atype, target=target
            )

    def _add_rewrite_policy(self, args: List[str]):
        """
        add rewrite policy <name> <rule_expression> <action>
        """
        flags  = self._parse_flags(args)
        name   = flags.get("_pos0", "")
        rule   = flags.get("-rule", flags.get("_pos1", ""))
        action = flags.get("-action", flags.get("_pos2", ""))
        goto   = flags.get("-goto", "")
        if name:
            self.rewrite_policies[name] = NSRewritePolicy(
                name=name, rule=rule, action=action, goto=goto
            )

    def _add_rewrite_action(self, args: List[str]):
        """
        add rewrite action <name> <type> <target> [-stringBuilderExpr <expr>]
        Types: replace, insert_http_header, delete_http_header,
               replace_http_res, insert_http_req_header, …
        """
        flags          = self._parse_flags(args)
        name           = flags.get("_pos0", "")
        atype          = flags.get("_pos1", "")
        target         = flags.get("_pos2", "")
        string_builder = flags.get("-stringbuilderexpr", "")
        if name:
            self.rewrite_actions[name] = NSRewriteAction(
                name=name, action_type=atype, target=target,
                string_builder=string_builder,
            )

    # ------------------------------------------------------------------
    # BIND handlers
    # ------------------------------------------------------------------

    def _bind_lb_vserver(self, args: List[str]):
        """
        bind lb vserver <vs_name> <serviceGroup_or_service>
            [-policyName <pol> -priority <n> -type REQUEST|RESPONSE]
        """
        flags   = self._parse_flags(args)
        vs_name = flags.get("_pos0", "")
        sg_svc  = flags.get("_pos1", "")          # serviceGroup or service name
        pol     = flags.get("-policyname", "")
        pri     = int(flags.get("-priority", 100) or 100)
        btype   = flags.get("-type", "REQUEST").upper()

        vs = self.lb_vservers.get(vs_name)
        if vs is None:
            return

        if pol:
            # It's a policy bind (responder/rewrite carried via lb vserver bind)
            # We can't easily tell type from here; store in both and deduplicate
            self.vserver_responder_bindings[vs_name].append((pol, pri, btype))
            self.vserver_rewrite_bindings[vs_name].append((pol, pri, btype))
        elif sg_svc:
            if sg_svc in self.service_groups:
                if sg_svc not in vs.service_groups:
                    vs.service_groups.append(sg_svc)
            elif sg_svc in self.services:
                if sg_svc not in vs.services:
                    vs.services.append(sg_svc)
            else:
                # Not yet seen – add speculatively so ordering is preserved
                vs.service_groups.append(sg_svc)

    def _bind_servicegroup(self, args: List[str]):
        """
        bind serviceGroup <sg_name> <server> <port> [-weight <w>]
        OR
        bind serviceGroup <sg_name> -monitorName <monitor>
        """
        flags   = self._parse_flags(args)
        sg_name = flags.get("_pos0", "")
        server  = flags.get("_pos1", "")
        port_s  = flags.get("_pos2", "")
        weight  = int(flags.get("-weight", 1) or 1)
        mon     = flags.get("-monitorname", "")

        sg = self.service_groups.get(sg_name)
        if sg is None:
            return

        if mon:
            if mon not in sg.monitors:
                sg.monitors.append(mon)
            return

        if server and port_s:
            try:
                port = int(port_s)
            except ValueError:
                port = 80
            sg.members.append((server, port, weight))

    def _bind_lb_monitor(self, args: List[str]):
        """
        bind lb monitor <entity_name> <monitor_name>
        OR
        bind serviceGroup <sg> -monitorName <mon>  (handled in _bind_servicegroup)
        """
        # Common form: bind lb monitor <servicegroupOrService> <monitorName>
        # Some NS versions write it reversed; we try both orderings.
        flags     = self._parse_flags(args)
        entity    = flags.get("_pos0", "")
        monitor   = flags.get("_pos1", flags.get("-monitorname", ""))

        if not monitor:
            return

        sg = self.service_groups.get(entity)
        if sg:
            if monitor not in sg.monitors:
                sg.monitors.append(monitor)
            return

        svc = self.services.get(entity)
        if svc:
            if monitor not in svc.monitors:
                svc.monitors.append(monitor)
            return

        # Try reversed – entity is actually the monitor name
        sg = self.service_groups.get(monitor)
        if sg:
            if entity not in sg.monitors:
                sg.monitors.append(entity)

    def _bind_cs_vserver(self, args: List[str]):
        """
        bind cs vserver <vs>
            -policyName <pol> -priority <n> [-targetLBVserver <lbvs>]
        OR  -lbvserver <lbvs>   (default binding, no policy)
        """
        flags   = self._parse_flags(args)
        vs_name = flags.get("_pos0", "")
        pol     = flags.get("-policyname", "")
        pri     = int(flags.get("-priority", 100) or 100)
        lbvs    = flags.get("-targetlbvserver", flags.get("-lbvserver", ""))

        vs = self.cs_vservers.get(vs_name)
        if vs is None:
            return

        if pol:
            # Resolve action name from the policy if available
            pol_obj     = self.cs_policies.get(pol)
            action_name = pol_obj.action if pol_obj else ""
            vs.cs_bindings.append((pri, pol, action_name))
        elif lbvs:
            vs.default_cs_action = lbvs

    def _bind_ssl_vserver(self, args: List[str]):
        """
        bind ssl vserver <vs>
            -certkeyName <certkey> [-SNICert]
        """
        flags   = self._parse_flags(args)
        vs_name = flags.get("_pos0", "")
        cert    = flags.get("-certkeyname", "")
        # Check for -SNICert flag (no value – just presence)
        sni     = any(a.lower() == "-snicert" for a in args)

        vs = self._get_vserver(vs_name)
        if vs and cert:
            if sni:
                if cert not in vs.ssl.sni_certs:
                    vs.ssl.sni_certs.append(cert)
            else:
                if cert not in vs.ssl.cert_key_names:
                    vs.ssl.cert_key_names.append(cert)

    # ------------------------------------------------------------------
    # SET handlers
    # ------------------------------------------------------------------

    def _set_ssl_vserver(self, args: List[str]):
        """
        set ssl vserver <vs>
            [-sslProfile <profile>]
            [-cipherName <cipher>]
            [-ssl3 ENABLED|DISABLED]
            [-tls1 ENABLED|DISABLED]
            [-tls11 ENABLED|DISABLED]
            [-tls12 ENABLED|DISABLED]
            [-clientAuth ENABLED|DISABLED]
        """
        flags       = self._parse_flags(args)
        vs_name     = flags.get("_pos0", "")
        profile     = flags.get("-sslprofile", "")
        cipher      = flags.get("-ciphername", flags.get("-cipher", ""))
        client_auth = flags.get("-clientauth", "")

        # Build enabled protocol list
        protocols: List[str] = []
        if flags.get("-ssl3", "").upper() == "ENABLED":
            protocols.append("SSLv3")
        if flags.get("-tls1", "").upper() == "ENABLED":
            protocols.append("TLSv1")
        if flags.get("-tls11", "").upper() == "ENABLED":
            protocols.append("TLSv1.1")
        if flags.get("-tls12", "").upper() == "ENABLED":
            protocols.append("TLSv1.2")
        if flags.get("-tls13", "").upper() == "ENABLED":
            protocols.append("TLSv1.3")

        vs = self._get_vserver(vs_name)
        if vs:
            if profile:
                vs.ssl.ssl_profile = profile
            if cipher:
                vs.ssl.cipher_alias = cipher
            if client_auth:
                vs.ssl.client_auth = client_auth
            if protocols:
                vs.ssl.ssl_protocols = protocols

    def _set_ns_timeout(self, args: List[str]):
        """
        set ns timeout [-httpClient <n>] [-httpServer <n>]
                       [-tcpClient <n>] [-tcpServer <n>] …
        """
        flags = self._parse_flags(args)
        for k, v in flags.items():
            if not k.startswith("_pos"):
                try:
                    self.ns_timeout[k.lstrip("-")] = int(v)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # LINK handlers
    # ------------------------------------------------------------------

    def _link_ssl_certkey(self, args: List[str]):
        """
        link ssl certKey <primary_cert> <chain_cert>
        Used to build certificate chains. Recorded for reference.
        """
        if len(args) < 2:
            return
        primary = args[0]
        linked  = args[1]
        ck = self.ssl_certkeys.get(primary)
        if ck:
            ck.linked_cert = linked


###############################################################################
# SECTION 4 – SkudonetMapper
###############################################################################

class SkudonetMapper:
    """
    Converts a populated NetScalerModel into a Skudonet-centric intermediate
    representation (plain Python dicts/lists) suitable for JSON serialisation
    and curl script generation.

    Key design decisions
    --------------------
    * Each lb/cs vserver becomes exactly one Skudonet Farm.
    * Protocol → Farm profile:
        HTTP, HTTPS, SSL, SSL_BRIDGE, SSL_TCP  →  "http"
        TCP, UDP, ANY, FTP, DNS, …             →  "l4xnat"
    * HTTP farms support multiple Services (backend groups with URL patterns).
      L4xNAT farms have backends directly on the farm.
    * For 'lb vserver' with multiple serviceGroups: each serviceGroup becomes
      a separate Service under the HTTP farm named after the serviceGroup.
    * For 'cs vserver': each CS policy binding becomes a Service with the
      URL/host pattern extracted from the policy rule expression.
    * Monitors → FarmGuardian.  One FG is registered per farm (the first
      distinct monitor found across all service groups of that farm).
      If different service groups have different monitors, a note is added
      and only the first is applied automatically.
    """

    # ------------------------------------------------------------------
    # LB method translation
    # ------------------------------------------------------------------
    LB_METHOD_MAP: Dict[str, str] = {
        "ROUNDROBIN":        "weight",
        "LEASTCONNECTION":   "leastconn",
        "SOURCEIPHASH":      "hash",
        "LEASTRESPONSETIME": "leastconn",    # no direct Skudonet equivalent
        "URLHASH":           "hash",
        "LEASTBANDWIDTH":    "leastconn",
        "LEASTPACKETS":      "leastconn",
        "TOKEN":             "weight",
        "SRCIPDESTIPHASH":   "hash",
        "SRCIPSRCPORTHASH":  "hash",
        "CALLIDHASH":        "hash",
        "CUSTOMLOAD":        "weight",       # custom load → fallback to weight
    }

    # Protocols that map to the HTTP farm profile
    HTTP_PROTOCOLS: set = {
        "HTTP", "HTTPS", "SSL", "SSL_BRIDGE", "SSL_TCP", "HTTP2"
    }

    def __init__(self, model: NetScalerModel):
        self.model          = model
        self.farms:         List[Dict[str, Any]] = []
        self.certs:         List[Dict[str, Any]] = []
        self.manual_review: List[str]            = []
        # Track sanitized names globally to prevent collisions
        self._used_names:   Dict[str, int]       = defaultdict(int)

    # ------------------------------------------------------------------
    def map(self) -> "SkudonetMapper":
        """Entry point. Run all conversion passes."""
        self._map_ssl_certs()
        self._map_lb_vservers()
        self._map_cs_vservers()
        return self

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _unique_farm_name(self, base: str) -> str:
        """Return a globally unique, sanitised farm/service name."""
        sane = self._sanitize(base)
        self._used_names[sane] += 1
        if self._used_names[sane] == 1:
            return sane
        return f"{sane}_{self._used_names[sane]}"

    @staticmethod
    def _sanitize(name: str) -> str:
        """
        Replace characters illegal in Skudonet farm/service identifiers.
        Skudonet allows: A-Z a-z 0-9 _ -
        Everything else becomes '_'.
        """
        return re.sub(r"[^A-Za-z0-9_\-]", "_", name)

    def _profile_for_protocol(self, protocol: str) -> str:
        """Return 'http' or 'l4xnat' based on the NetScaler protocol string."""
        return "http" if protocol.upper() in self.HTTP_PROTOCOLS else "l4xnat"

    def _lb_algorithm(self, lb_method: str) -> str:
        """Translate a NetScaler lb method name to a Skudonet algorithm."""
        algo = self.LB_METHOD_MAP.get(lb_method.upper(), "weight")
        return algo

    # ------------------------------------------------------------------
    # SSL certificates
    # ------------------------------------------------------------------

    def _map_ssl_certs(self):
        """
        Build the certificate list.  Certificates must be uploaded to Skudonet
        before farms that reference them can be created.
        """
        for name, ck in self.model.ssl_certkeys.items():
            self.certs.append({
                "name":        name,
                "cert_file":   ck.cert_file,
                "key_file":    ck.key_file,
                "cert_type":   ck.cert_type,
                "linked_cert": ck.linked_cert,
                "_upload_note": (
                    "Upload cert/key PEM files to Skudonet then POST to "
                    "/zapi/v4.0/zapi.cgi/system/certificates"
                ),
            })

    # ------------------------------------------------------------------
    # LB vservers
    # ------------------------------------------------------------------

    def _map_lb_vservers(self):
        for name, vs in self.model.lb_vservers.items():
            farm = self._vserver_to_farm(vs)
            if farm:
                self.farms.append(farm)

    # ------------------------------------------------------------------
    # CS vservers
    # ------------------------------------------------------------------

    def _map_cs_vservers(self):
        for name, vs in self.model.cs_vservers.items():
            farm = self._cs_vserver_to_farm(vs)
            if farm:
                self.farms.append(farm)

    # ------------------------------------------------------------------
    # Core: lb vserver → Farm
    # ------------------------------------------------------------------

    def _vserver_to_farm(self, vs: NSVServer) -> Dict[str, Any]:
        """
        Convert a single lb vserver to a Skudonet farm dict.
        Multiple serviceGroups bound to the same vserver become multiple
        Services within one HTTP farm, or flat backends in an L4xNAT farm.
        """
        profile = self._profile_for_protocol(vs.protocol)
        is_https = vs.protocol in ("HTTPS", "SSL", "SSL_BRIDGE", "SSL_TCP")

        farm: Dict[str, Any] = {
            "farmname":       self._sanitize(vs.name),
            "_ns_name":       vs.name,
            "_ns_type":       "lb_vserver",
            "profile":        profile,
            "vip":            vs.ip,
            "vport":          vs.port,
            "status":         "up" if vs.state == "ENABLED" else "down",
            "algorithm":      self._lb_algorithm(vs.lb_method),
            "_ns_lb_method":  vs.lb_method,
            "https_listener": is_https,
            "services":       [],
            "ssl":            {},
            "persistence":    {},
            "farmguardian":   [],
            "rewrites":       [],
            "redirects":      [],
            "_notes":         [],
            "_ns_comment":    vs.comment,
        }

        if vs.state == "DISABLED":
            farm["_notes"].append(
                "This vserver was DISABLED in NetScaler – farm will be stopped"
            )

        if vs.timeout:
            farm["timeout"] = vs.timeout

        if vs.backup_vserver:
            farm["_notes"].append(
                f"Backup vserver '{vs.backup_vserver}' – configure failover manually"
            )
            self.manual_review.append(
                f"Farm '{vs.name}' has backup vserver '{vs.backup_vserver}' – "
                f"no direct Skudonet equivalent; consider a separate farm or DR config"
            )

        farm["persistence"] = self._map_persistence(vs.persistence, profile)
        if is_https:
            farm["ssl"] = self._map_ssl(vs.ssl)

        # Build services
        if profile == "http":
            services = self._build_http_services(vs)
            farm["services"] = services
        else:
            # L4xNAT: flatten all backends into the farm's backend list
            backends = self._collect_backends_flat(vs)
            farm["backends"] = backends

        # Farm Guardian (first monitor found)
        fg = self._first_farmguardian(vs)
        if fg:
            farm["farmguardian"] = [fg]

        # Check for multiple different monitors across service groups
        all_monitors = self._all_monitor_names(vs)
        if len(all_monitors) > 1:
            farm["_notes"].append(
                f"Multiple health monitors found: {all_monitors}. "
                f"Only the first ({all_monitors[0]}) is applied as FarmGuardian. "
                f"Review others manually."
            )
            self.manual_review.append(
                f"Farm '{vs.name}' has multiple monitors {all_monitors}; "
                f"only '{all_monitors[0]}' was applied"
            )

        # Responder / rewrite policies bound to this vserver
        self._map_responder_policies_for_vs(vs.name, farm)
        self._map_rewrite_policies_for_vs(vs.name, farm)

        return farm

    # ------------------------------------------------------------------
    # Core: cs vserver → Farm with Services
    # ------------------------------------------------------------------

    def _cs_vserver_to_farm(self, vs: NSVServer) -> Dict[str, Any]:
        """
        Convert a CS vserver to a Skudonet HTTP farm with multiple services.

        CS policy evaluation order in NetScaler: lower priority number = higher
        priority.  In Skudonet, services are matched in the order they are
        listed, so we sort by NS priority ascending.

        The default CS action (no policy match) becomes the last 'catch-all'
        service with urlp='/'.
        """
        profile  = self._profile_for_protocol(vs.protocol)
        is_https = vs.protocol in ("HTTPS", "SSL", "SSL_BRIDGE", "SSL_TCP")

        farm: Dict[str, Any] = {
            "farmname":       self._sanitize(vs.name),
            "_ns_name":       vs.name,
            "_ns_type":       "cs_vserver",
            "profile":        profile,
            "vip":            vs.ip,
            "vport":          vs.port,
            "status":         "up" if vs.state == "ENABLED" else "down",
            "algorithm":      self._lb_algorithm(vs.lb_method),
            "_ns_lb_method":  vs.lb_method,
            "https_listener": is_https,
            "services":       [],
            "ssl":            {},
            "persistence":    {},
            "farmguardian":   [],
            "rewrites":       [],
            "redirects":      [],
            "_notes":         [
                "Converted from CS vserver – verify service URL matching order."
            ],
            "_ns_comment":    vs.comment,
        }

        if vs.state == "DISABLED":
            farm["_notes"].append(
                "CS vserver was DISABLED in NetScaler – farm will be stopped"
            )

        farm["persistence"] = self._map_persistence(vs.persistence, profile)
        if is_https:
            farm["ssl"] = self._map_ssl(vs.ssl)

        # Sort CS bindings: lower priority number = higher priority in NS
        sorted_bindings = sorted(vs.cs_bindings, key=lambda x: x[0])

        for pri, pol_name, action_name in sorted_bindings:
            svc = self._cs_policy_to_service(pol_name, action_name, pri)
            if svc:
                farm["services"].append(svc)

        # Default backend: catch-all service last in the list
        if vs.default_cs_action:
            default_svc = self._cs_default_service(vs.default_cs_action)
            if default_svc:
                farm["services"].append(default_svc)
        elif not farm["services"]:
            farm["_notes"].append(
                "No CS policies or default action found – farm has no backends"
            )
            self.manual_review.append(
                f"CS vserver '{vs.name}' has no policies or default action"
            )

        # FarmGuardian: collect from all target LB vservers
        fg = self._first_fg_from_cs(vs)
        if fg:
            farm["farmguardian"] = [fg]

        self._map_responder_policies_for_vs(vs.name, farm)
        self._map_rewrite_policies_for_vs(vs.name, farm)

        return farm

    # ------------------------------------------------------------------
    # HTTP services
    # ------------------------------------------------------------------

    def _build_http_services(self, vs: NSVServer) -> List[Dict[str, Any]]:
        """
        Build HTTP farm services from bound serviceGroups and services.
        Each serviceGroup → one Service.  If there is only one serviceGroup,
        the service id is 'default'.  If multiple, the name of the SG is used.
        """
        services: List[Dict[str, Any]] = []
        all_sg  = vs.service_groups
        all_svc = vs.services
        use_default_id = (len(all_sg) + len(all_svc)) == 1

        for sg_name in all_sg:
            svc_id = "default" if use_default_id else self._sanitize(sg_name)
            sg     = self.model.service_groups.get(sg_name)
            if sg is None:
                self.manual_review.append(
                    f"Service group '{sg_name}' referenced by lb vserver "
                    f"'{vs.name}' was not found in the config"
                )
                continue

            backends = self._backends_from_sg(sg_name)
            fg       = None
            if sg.monitors:
                fg = self._monitor_to_farmguardian(sg.monitors[0])

            services.append({
                "id":           svc_id,
                "_ns_sg":       sg_name,
                "urlp":         "/",
                "hostheader":   "",
                "backends":     backends,
                "farmguardian": fg,
                "_notes":       [] if sg.state == "ENABLED" else [
                    f"Service group '{sg_name}' was DISABLED in NetScaler"
                ],
            })

        for svc_name in all_svc:
            svc_id = "default" if use_default_id else self._sanitize(svc_name)
            svc    = self.model.services.get(svc_name)
            if svc is None:
                self.manual_review.append(
                    f"Service '{svc_name}' referenced by lb vserver "
                    f"'{vs.name}' was not found"
                )
                continue

            ip       = self.model._resolve_ip(svc.server)
            backends = [{
                "ip":     ip,
                "port":   svc.port,
                "weight": 1,
                "status": "up" if svc.state == "ENABLED" else "maintenance",
                "_ns_service": svc_name,
            }]
            fg = None
            if svc.monitors:
                fg = self._monitor_to_farmguardian(svc.monitors[0])

            services.append({
                "id":           svc_id,
                "_ns_service":  svc_name,
                "urlp":         "/",
                "hostheader":   "",
                "backends":     backends,
                "farmguardian": fg,
                "_notes":       [],
            })

        if not services:
            # Create a placeholder service with no backends
            services.append({
                "id":           "default",
                "urlp":         "/",
                "hostheader":   "",
                "backends":     [],
                "farmguardian": None,
                "_notes":       ["No service groups or services bound – add backends manually"],
            })
            self.manual_review.append(
                f"lb vserver '{vs.name}' has no bound service groups or services"
            )

        return services

    # ------------------------------------------------------------------
    # L4xNAT flat backends
    # ------------------------------------------------------------------

    def _collect_backends_flat(self, vs: NSVServer) -> List[Dict[str, Any]]:
        """Collect all backends across all service groups / services for L4xNAT."""
        backends: List[Dict[str, Any]] = []
        for sg_name in vs.service_groups:
            backends.extend(self._backends_from_sg(sg_name))
        for svc_name in vs.services:
            svc = self.model.services.get(svc_name)
            if not svc:
                continue
            ip = self.model._resolve_ip(svc.server)
            backends.append({
                "ip":     ip,
                "port":   svc.port,
                "weight": 1,
                "status": "up" if svc.state == "ENABLED" else "maintenance",
                "_ns_service": svc_name,
            })
        return backends

    def _backends_from_sg(self, sg_name: str) -> List[Dict[str, Any]]:
        """Return Skudonet backend dicts from a NetScaler service group."""
        sg = self.model.service_groups.get(sg_name)
        if not sg:
            return []
        backends: List[Dict[str, Any]] = []
        for server_name, port, weight in sg.members:
            ip = self.model._resolve_ip(server_name)
            backends.append({
                "ip":            ip,
                "port":          port,
                "weight":        weight,
                "status":        "up" if sg.state == "ENABLED" else "maintenance",
                "_ns_sg":        sg_name,
                "_ns_server":    server_name,
            })
        if not sg.members:
            self.manual_review.append(
                f"Service group '{sg_name}' has no members bound"
            )
        return backends

    # ------------------------------------------------------------------
    # CS policy → Service
    # ------------------------------------------------------------------

    def _cs_policy_to_service(self, pol_name: str, action_name: str,
                               priority: int) -> Optional[Dict[str, Any]]:
        """
        Convert one CS policy binding to a Skudonet HTTP Service.

        URL / Host are extracted from the NS PIXL expression using regex
        heuristics.  Complex or composite expressions are preserved as
        comments with a manual-review note.
        """
        pol = self.model.cs_policies.get(pol_name)
        if pol is None:
            self.manual_review.append(
                f"CS policy '{pol_name}' is referenced in a bind but was not found"
            )
            return None

        # Resolve action → target LB vserver
        action_name = action_name or pol.action
        action      = self.model.cs_actions.get(action_name)
        target_lb   = action.target_lb if action else ""

        url_pattern, hostname = self._extract_cs_rule_patterns(pol.rule)
        rule_is_complex       = self._cs_rule_is_complex(pol.rule)

        notes: List[str] = []
        if rule_is_complex:
            notes.append(
                f"Complex/composite CS rule cannot be fully auto-converted. "
                f"Original: {pol.rule}"
            )
            self.manual_review.append(
                f"CS policy '{pol_name}' has a complex rule: {pol.rule}"
            )

        svc: Dict[str, Any] = {
            "id":           self._sanitize(pol_name),
            "_ns_policy":   pol_name,
            "_ns_action":   action_name,
            "_ns_rule":     pol.rule,
            "_ns_priority": priority,
            "urlp":         url_pattern,
            "hostheader":   hostname,
            "backends":     [],
            "farmguardian": None,
            "_notes":       notes,
        }

        # Resolve backends from the target LB vserver
        if target_lb:
            target_vs = self.model.lb_vservers.get(target_lb)
            if target_vs:
                svc["backends"] = self._collect_backends_flat(target_vs)
                if not svc["backends"]:
                    # Try HTTP-style service collection
                    svc["backends"] = [
                        be
                        for http_svc in self._build_http_services(target_vs)
                        for be in http_svc.get("backends", [])
                    ]
                mon_name = self._first_monitor_name_for_vs(target_vs)
                if mon_name:
                    svc["farmguardian"] = self._monitor_to_farmguardian(mon_name)
            else:
                notes.append(
                    f"Target LB vserver '{target_lb}' not found – add backends manually"
                )
                self.manual_review.append(
                    f"CS policy '{pol_name}' → action '{action_name}' → "
                    f"target '{target_lb}' was not found in lb_vservers"
                )
        else:
            notes.append(
                f"No resolvable target LB vserver for CS policy '{pol_name}' – "
                f"add backends manually"
            )
            self.manual_review.append(
                f"CS policy '{pol_name}' has no resolvable action/target"
            )

        return svc

    def _cs_default_service(self, target_lb: str) -> Optional[Dict[str, Any]]:
        """Build the default/catch-all service from the CS default target."""
        notes: List[str] = ["Default CS service (catches all unmatched requests)"]

        svc: Dict[str, Any] = {
            "id":                    "default",
            "_ns_default_target":    target_lb,
            "urlp":                  "/",
            "hostheader":            "",
            "backends":              [],
            "farmguardian":          None,
            "_notes":                notes,
        }

        target_vs = self.model.lb_vservers.get(target_lb)
        if target_vs:
            svc["backends"] = self._collect_backends_flat(target_vs)
            if not svc["backends"]:
                svc["backends"] = [
                    be
                    for http_svc in self._build_http_services(target_vs)
                    for be in http_svc.get("backends", [])
                ]
            mon_name = self._first_monitor_name_for_vs(target_vs)
            if mon_name:
                svc["farmguardian"] = self._monitor_to_farmguardian(mon_name)
        else:
            notes.append(
                f"Default target LB vserver '{target_lb}' not found – add backends manually"
            )
            self.manual_review.append(
                f"CS vserver default target '{target_lb}' not found"
            )

        return svc

    # ------------------------------------------------------------------
    # CS rule expression parsing (best-effort)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cs_rule_patterns(rule: str) -> Tuple[str, str]:
        """
        Attempt to extract (url_pattern, hostname) from a NetScaler PIXL
        or classic CS policy rule expression.

        Common patterns handled:
          HTTP.REQ.URL.STARTSWITH("/api")            → url="/api"
          HTTP.REQ.URL.CONTAINS("/shop")             → url="/shop"
          HTTP.REQ.URL.EQ("/home")                   → url="/home"
          HTTP.REQ.URL.MATCHES_GLOB("/img/*")        → url="/img/*"
          HTTP.REQ.HOSTNAME.EQ("app.example.com")    → host="app.example.com"
          HTTP.REQ.HOST.EQ("api.example.com")        → host="api.example.com"
          REQ.HTTP.URL startswith "/admin"  (classic) → url="/admin"
        """
        url  = ""
        host = ""

        # Modern PIXL – URL
        url_m = re.search(
            r'HTTP\.REQ\.URL\s*\.\s*(?:STARTSWITH|CONTAINS|EQ|MATCHES_GLOB)'
            r'\s*\(\s*["\']([^"\']+)["\']\s*\)',
            rule, re.IGNORECASE
        )
        if url_m:
            url = url_m.group(1)
            if not url.startswith("/"):
                url = "/" + url

        # Classic expression – URL startswith
        if not url:
            classic_m = re.search(
                r'REQ\.HTTP\.URL\s+(?:startswith|contains|eq)\s+"([^"]+)"',
                rule, re.IGNORECASE
            )
            if classic_m:
                url = classic_m.group(1)
                if not url.startswith("/"):
                    url = "/" + url

        # Modern PIXL – Hostname
        host_m = re.search(
            r'HTTP\.REQ\.(?:HOSTNAME|HOST)(?:\.[A-Z_]+\([^)]*\))?'
            r'\s*\.\s*(?:EQ|CONTAINS)\s*\(\s*["\']([^"\']+)["\']\s*\)',
            rule, re.IGNORECASE
        )
        if host_m:
            host = host_m.group(1)

        # Classic – HOST header
        if not host:
            host_classic = re.search(
                r'REQ\.HTTP\.HEADER\s+HOST\s+(?:eq|contains)\s+"([^"]+)"',
                rule, re.IGNORECASE
            )
            if host_classic:
                host = host_classic.group(1)

        return url or "/", host

    @staticmethod
    def _cs_rule_is_complex(rule: str) -> bool:
        """
        Return True if the rule contains boolean operators (&&, ||, AND, OR)
        which indicate a composite expression needing manual review.
        """
        if not rule:
            return False
        return bool(
            re.search(r'\b(AND|OR)\b|&&|\|\|', rule, re.IGNORECASE)
        )

    # ------------------------------------------------------------------
    # FarmGuardian / Monitor mapping
    # ------------------------------------------------------------------

    def _monitor_to_farmguardian(self, mon_name: str) -> Optional[Dict[str, Any]]:
        """
        Convert a NetScaler monitor to a Skudonet FarmGuardian definition.

        FarmGuardian uses Nagios-style check plugins:
          check_http  – port based HTTP check with optional URL and string
          check_tcp   – basic TCP connect (+ optional send/expect strings)
          check_ping  – ICMP ping with warn/crit thresholds
        """
        mon = self.model.monitors.get(mon_name)
        if mon is None:
            return None
        if mon.state == "DISABLED":
            return None

        mtype               = mon.type.upper()
        check_cmd: str
        params:    str
        need_review = False

        if mtype in ("HTTP", "HTTP-ECV", "HTTP-INLINE"):
            check_cmd = "check_http"
            params    = "-H $HOST -p $PORT"

            # Extract path from 'GET /url HTTP/1.x' style httpRequest
            if mon.http_request:
                path_m = re.match(r'\w+\s+(\S+)', mon.http_request)
                if path_m:
                    params += f" -u {path_m.group(1)}"

            if mon.recv:
                # -s expects a string in the HTTP body
                params += f" -s '{mon.recv}'"

            if mon.dest_port:
                params = params.replace("-p $PORT", f"-p {mon.dest_port}")

        elif mtype in ("HTTPS", "HTTP_SECURE"):
            check_cmd   = "check_http"
            params      = "-H $HOST -p $PORT --ssl"
            if mon.http_request:
                path_m = re.match(r'\w+\s+(\S+)', mon.http_request)
                if path_m:
                    params += f" -u {path_m.group(1)}"
            if mon.recv:
                params += f" -s '{mon.recv}'"

        elif mtype in ("TCP", "TCP-ECV"):
            check_cmd = "check_tcp"
            params    = "-H $HOST -p $PORT"
            if mon.send:
                params += f" -s '{mon.send}'"
            if mon.recv:
                params += f" -e '{mon.recv}'"
            if mon.dest_port:
                params = params.replace("-p $PORT", f"-p {mon.dest_port}")

        elif mtype in ("PING", "ICMP"):
            check_cmd = "check_ping"
            params    = "-H $HOST -w 100,5% -c 500,10% -p 5"

        elif mtype == "DNS":
            check_cmd   = "check_dns"
            params      = "-H $HOST -p $PORT"
            need_review = True

        elif mtype in ("SMTP", "FTP", "IMAP", "POP3", "NNTP"):
            check_cmd   = "check_tcp"
            params      = "-H $HOST -p $PORT"
            need_review = True

        else:
            # Unknown type – default to TCP check with a review note
            check_cmd   = "check_tcp"
            params      = "-H $HOST -p $PORT"
            need_review = True

        if need_review:
            self.manual_review.append(
                f"Monitor '{mon_name}' type '{mtype}' has no direct Skudonet "
                f"FarmGuardian equivalent – defaulted to {check_cmd}"
            )

        fg: Dict[str, Any] = {
            "name":      f"fg_{self._sanitize(mon_name)}",
            "_ns_name":  mon_name,
            "_ns_type":  mtype,
            "command":   check_cmd,
            "params":    params,
            "interval":  mon.interval,
            "timeout":   mon.response_timeout,
            "log":       True,
        }

        if mon.raw_params:
            fg["_ns_raw_params"] = mon.raw_params

        return fg

    def _first_monitor_name_for_vs(self, vs: NSVServer) -> Optional[str]:
        """Return the name of the first monitor found across a vserver's SGs."""
        for sg_name in vs.service_groups:
            sg = self.model.service_groups.get(sg_name)
            if sg and sg.monitors:
                return sg.monitors[0]
        for svc_name in vs.services:
            svc = self.model.services.get(svc_name)
            if svc and svc.monitors:
                return svc.monitors[0]
        return None

    def _all_monitor_names(self, vs: NSVServer) -> List[str]:
        """Return all distinct monitor names across a vserver's SGs/services."""
        seen: List[str] = []
        for sg_name in vs.service_groups:
            sg = self.model.service_groups.get(sg_name)
            if sg:
                for m in sg.monitors:
                    if m not in seen:
                        seen.append(m)
        for svc_name in vs.services:
            svc = self.model.services.get(svc_name)
            if svc:
                for m in svc.monitors:
                    if m not in seen:
                        seen.append(m)
        return seen

    def _first_farmguardian(self, vs: NSVServer) -> Optional[Dict[str, Any]]:
        mon_name = self._first_monitor_name_for_vs(vs)
        if mon_name:
            return self._monitor_to_farmguardian(mon_name)
        return None

    def _first_fg_from_cs(self, vs: NSVServer) -> Optional[Dict[str, Any]]:
        """For a CS vserver, look into its target LB vservers for monitors."""
        for _pri, _pol, _act in vs.cs_bindings:
            pol = self.model.cs_policies.get(_pol)
            if not pol:
                continue
            act = self.model.cs_actions.get(pol.action)
            if not act:
                continue
            target = self.model.lb_vservers.get(act.target_lb)
            if target:
                fg = self._first_farmguardian(target)
                if fg:
                    return fg
        if vs.default_cs_action:
            target = self.model.lb_vservers.get(vs.default_cs_action)
            if target:
                return self._first_farmguardian(target)
        return None

    # ------------------------------------------------------------------
    # Persistence mapping
    # ------------------------------------------------------------------

    def _map_persistence(self, pers: NSPersistence,
                          profile: str) -> Dict[str, Any]:
        """
        Map NetScaler persistence type to Skudonet persistence configuration.

        HTTP profile persistence modes: IP, COOKIE, none
        L4xNAT persistence modes:       ip, none

        NetScaler → Skudonet:
          SOURCEIP       → ip / IP
          COOKIEINSERT   → COOKIE (HTTP only)
          COOKIEPASSIVE  → COOKIE (HTTP only)
          SSLSESSIONID   → IP (no direct equivalent; noted)
          RULE           → IP (no direct equivalent; noted)
          DESTIP         → no equivalent; noted
          NONE / empty   → no persistence
        """
        ptype = (pers.type or "").upper()
        if not ptype or ptype == "NONE":
            return {}

        result: Dict[str, Any] = {}

        if profile == "l4xnat":
            # L4xNAT only supports IP-based persistence
            result["persistence"] = "ip"
            result["ttl"]         = pers.timeout or 180
            if ptype not in ("SOURCEIP",):
                result["_note"] = (
                    f"NetScaler persistence '{ptype}' mapped to IP persistence "
                    f"for L4xNAT profile – verify this is acceptable"
                )
        else:
            # HTTP profile
            if ptype == "SOURCEIP":
                result["persistence"] = "IP"
                result["ttl"]         = pers.timeout or 600

            elif ptype in ("COOKIEINSERT", "COOKIEPASSIVE"):
                result["persistence"] = "COOKIE"
                result["ttl"]         = pers.timeout or 600
                result["cookie"]      = pers.cookie_name or "SERVERID"
                if ptype == "COOKIEPASSIVE":
                    result["_note"] = (
                        "COOKIEPASSIVE: Skudonet inserts its own cookie. "
                        "If the app already sets a cookie, use COOKIE mode "
                        "and select the cookie name manually."
                    )

            elif ptype == "SSLSESSIONID":
                result["persistence"] = "IP"
                result["ttl"]         = pers.timeout or 600
                result["_note"] = (
                    "SSLSESSIONID persistence has no direct Skudonet equivalent. "
                    "Mapped to IP persistence – review if SSL session affinity "
                    "is required."
                )
                self.manual_review.append(
                    "SSLSESSIONID persistence mapped to IP – review required"
                )

            elif ptype == "RULE":
                result["persistence"] = "IP"
                result["ttl"]         = pers.timeout or 600
                result["_note"] = (
                    "RULE-based persistence cannot be directly converted. "
                    "Defaulting to IP persistence."
                )
                self.manual_review.append(
                    "RULE persistence cannot be auto-converted – review"
                )

            elif ptype == "DESTIP":
                result["_note"] = (
                    "DESTIP persistence has no equivalent in Skudonet – "
                    "configure manually if required"
                )
                self.manual_review.append(
                    "DESTIP persistence has no Skudonet equivalent"
                )

            elif ptype == "SRCIPDESTIP":
                result["persistence"] = "IP"
                result["ttl"]         = pers.timeout or 600
                result["_note"] = (
                    "SRCIPDESTIP persistence mapped to IP persistence"
                )

            else:
                result["persistence"] = "IP"
                result["ttl"]         = pers.timeout or 600
                result["_note"] = (
                    f"Unknown persistence type '{ptype}' – defaulting to IP"
                )
                self.manual_review.append(
                    f"Unknown persistence '{ptype}' defaulted to IP"
                )

        return result

    # ------------------------------------------------------------------
    # SSL mapping
    # ------------------------------------------------------------------

    def _map_ssl(self, ssl: NSSSLConfig) -> Dict[str, Any]:
        """
        Map NSSSLConfig to a Skudonet SSL configuration dict.

        Notes:
        - Certificate files must be uploaded to Skudonet separately.
        - Cipher aliases from NetScaler must be translated to Skudonet
          cipher names or OpenSSL cipher strings manually.
        - SNI certificates are listed separately; Skudonet supports SNI
          via multiple certificates on an HTTPS farm.
        """
        if not (ssl.cert_key_names or ssl.sni_certs or ssl.ssl_profile):
            return {}

        ssl_config: Dict[str, Any] = {
            "ciphers":     ssl.cipher_alias or "HIGH:!aNULL:!MD5",
            "certificates": ssl.cert_key_names,
            "sni_certs":    ssl.sni_certs,
        }

        if ssl.ssl_profile:
            ssl_config["_ns_ssl_profile"] = ssl.ssl_profile
            ssl_config["_note_profile"] = (
                f"SSL profile '{ssl.ssl_profile}' must be manually mapped to "
                f"Skudonet cipher/protocol settings"
            )

        if ssl.ssl_protocols:
            ssl_config["protocols"] = ssl.ssl_protocols
            if "SSLv3" in ssl.ssl_protocols or "TLSv1" in ssl.ssl_protocols:
                ssl_config["_security_warning"] = (
                    "SSLv3 / TLSv1.0 are deprecated and insecure – "
                    "consider removing them"
                )

        if ssl.client_auth:
            ssl_config["client_cert"] = ssl.client_auth
            if ssl.client_auth.upper() == "ENABLED":
                ssl_config["_note_client_auth"] = (
                    "Client certificate authentication – configure CA cert "
                    "in Skudonet manually"
                )

        if ssl.cipher_alias:
            ssl_config["_note_cipher"] = (
                f"NetScaler cipher alias '{ssl.cipher_alias}' – translate to "
                f"OpenSSL cipher string in Skudonet"
            )

        return ssl_config

    # ------------------------------------------------------------------
    # Responder / Rewrite policy mapping
    # ------------------------------------------------------------------

    def _map_responder_policies_for_vs(self, vs_name: str,
                                        farm: Dict[str, Any]):
        """
        Convert responder policies bound to a vserver.

        - redirect / respondwith → Skudonet farm redirect entry
        - noop                   → skip
        - other                  → manual review note
        """
        bindings = self.model.vserver_responder_bindings.get(vs_name, [])
        if not bindings:
            return

        # Deduplicate: a policy may appear in both responder and rewrite tables
        seen_pols: set = set()
        for pol_name, pri, btype in sorted(bindings, key=lambda x: x[1]):
            if pol_name in seen_pols:
                continue

            # Only handle if it's actually a responder policy (not rewrite)
            pol = self.model.responder_policies.get(pol_name)
            if pol is None:
                continue

            seen_pols.add(pol_name)

            action = self.model.responder_actions.get(pol.action)
            if not action:
                farm["_notes"].append(
                    f"Responder policy '{pol_name}' – action '{pol.action}' not found"
                )
                self.manual_review.append(
                    f"Responder policy '{pol_name}' on '{vs_name}': "
                    f"action '{pol.action}' not in config"
                )
                continue

            atype = action.action_type.lower()

            if atype in ("redirect",):
                farm["redirects"].append({
                    "_ns_policy":  pol_name,
                    "_ns_rule":    pol.rule,
                    "_ns_action":  pol.action,
                    "redirect_url": action.target,
                    "redirect_code": 302,
                    "_note": (
                        "Verify URL. Complex NS expressions in the target "
                        "must be translated to a static URL manually."
                    ),
                })

            elif atype in ("respondwith", "respondwithhtmlpage"):
                farm["_notes"].append(
                    f"Responder action '{action.name}' type '{atype}' "
                    f"generates a custom response – configure manually in Skudonet"
                )
                self.manual_review.append(
                    f"Responder action '{action.name}' ('{atype}') on "
                    f"'{vs_name}' needs manual Skudonet equivalent"
                )

            elif atype in ("noop", "reset"):
                pass  # No-op; skip

            else:
                farm["_notes"].append(
                    f"Responder action '{action.name}' type '{atype}' "
                    f"cannot be auto-converted"
                )
                self.manual_review.append(
                    f"Responder action '{action.name}' ('{atype}') on "
                    f"'{vs_name}' has no Skudonet equivalent"
                )

    def _map_rewrite_policies_for_vs(self, vs_name: str,
                                      farm: Dict[str, Any]):
        """
        Convert rewrite policies bound to a vserver.

        Skudonet HTTP farms support:
          - AddRequestHeader / ModifyRequestHeader
          - AddResponseHeader / ModifyResponseHeader
          - RewriteURL (limited)

        These are recorded as structured dicts for the operator to configure
        in the Skudonet UI or via the API.  The NS expression/target is
        preserved for reference.
        """
        bindings = self.model.vserver_rewrite_bindings.get(vs_name, [])
        if not bindings:
            return

        seen_pols: set = set()
        for pol_name, pri, btype in sorted(bindings, key=lambda x: x[1]):
            if pol_name in seen_pols:
                continue

            pol = self.model.rewrite_policies.get(pol_name)
            if pol is None:
                continue  # It was a responder policy; skip here

            seen_pols.add(pol_name)

            action = self.model.rewrite_actions.get(pol.action)
            if not action:
                farm["_notes"].append(
                    f"Rewrite policy '{pol_name}' – action '{pol.action}' not found"
                )
                self.manual_review.append(
                    f"Rewrite policy '{pol_name}' on '{vs_name}': "
                    f"action '{pol.action}' not in config"
                )
                continue

            atype  = action.action_type.lower()
            target = action.target
            expr   = action.string_builder

            rw: Dict[str, Any] = {
                "_ns_policy":  pol_name,
                "_ns_action":  pol.action,
                "_ns_rule":    pol.rule,
                "_ns_type":    action.action_type,
                "_ns_target":  target,
                "_ns_expr":    expr,
            }

            if atype == "insert_http_header":
                rw["type"]        = "AddRequestHeader"
                rw["header_name"] = target
                rw["header_value"] = expr
                rw["_note"] = (
                    "Use Skudonet HTTP farm 'AddRequestHeader' directive"
                )
            elif atype == "insert_http_req_header":
                rw["type"]         = "AddRequestHeader"
                rw["header_name"]  = target
                rw["header_value"] = expr
                rw["_note"] = "Add request header in Skudonet HTTP farm"
            elif atype in ("replace", "replace_http_res"):
                rw["type"] = "ModifyHeader"
                rw["_note"] = (
                    "Modify header or URL – implement via Skudonet directives"
                )
            elif atype == "delete_http_header":
                rw["type"] = "RemoveRequestHeader"
                rw["header_name"] = target
                rw["_note"] = "Remove request header in Skudonet HTTP farm"
            else:
                rw["type"] = "MANUAL_REVIEW"
                rw["_note"] = (
                    f"Rewrite type '{atype}' has no direct Skudonet equivalent"
                )
                self.manual_review.append(
                    f"Rewrite action '{action.name}' ('{atype}') on "
                    f"'{vs_name}' needs manual translation"
                )

            farm["rewrites"].append(rw)


###############################################################################
# SECTION 5 – SkudonetConfigWriter
###############################################################################

class SkudonetConfigWriter:
    """
    Serialises the SkudonetMapper result to a well-structured JSON file
    (skudonet_config.json).

    The JSON schema mirrors common Skudonet ZAPI v4.0 response shapes
    to make the output easy to consume by scripts or further tooling.
    """

    def __init__(self, mapper: SkudonetMapper, output_dir: str):
        self.mapper     = mapper
        self.output_dir = output_dir

    def write(self) -> str:
        """Write skudonet_config.json and return the absolute file path."""
        config = {
            "_generator":          "ns_to_skudonet.py v1.0.0",
            "_source":             "Citrix ADC (NetScaler) ns.conf",
            "_notes": [
                "Review all '_notes' fields before applying.",
                "Upload SSL certificates before creating HTTPS farms.",
                "Items in 'manual_review_items' require manual configuration.",
            ],
            "certificates":        self.mapper.certs,
            "farms":               self.mapper.farms,
            "manual_review_items": self.mapper.manual_review,
        }

        path = os.path.join(self.output_dir, "skudonet_config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2, default=str)

        return os.path.abspath(path)


###############################################################################
# SECTION 6 – SkudonetAPIScriptWriter
###############################################################################

class SkudonetAPIScriptWriter:
    """
    Generates a bash shell script (skudonet_apply.sh) of curl commands that
    call the Skudonet ZAPI v4.0 REST API to apply the converted configuration.

    Variables BASE_URL and API_KEY must be exported in the environment before
    running the script.

    Script structure:
      1. Header / preamble
      2. SSL certificate upload stubs
      3. Per-farm sections:
         a. Create farm
         b. Configure farm profile (HTTP or L4xNAT)
         c. Bind SSL certificate(s)
         d. Create service(s)  [HTTP farms]
         e. Add backend(s)
         f. Set up FarmGuardian
         g. Redirect / rewrite notes
         h. Start / stop farm
      4. Footer
    """

    ZAPI = "/zapi/v4.0/zapi.cgi"

    def __init__(self, mapper: SkudonetMapper, output_dir: str):
        self.mapper     = mapper
        self.output_dir = output_dir
        self._lines:    List[str] = []

    # ------------------------------------------------------------------
    def write(self) -> str:
        """Write skudonet_apply.sh and return the absolute file path."""
        self._write_header()
        self._write_cert_section()
        self._write_farms_section()
        self._write_footer()

        path = os.path.join(self.output_dir, "skudonet_apply.sh")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self._lines) + "\n")

        # Make executable on Unix/Mac (ignored on Windows)
        try:
            import stat as _stat
            os.chmod(
                path,
                os.stat(path).st_mode
                | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH,
            )
        except OSError:
            pass

        return os.path.abspath(path)

    # ------------------------------------------------------------------
    # Low-level line writers
    # ------------------------------------------------------------------

    def _w(self, line: str = ""):
        self._lines.append(line)

    def _comment(self, text: str):
        self._w(f"# {text}")

    def _banner(self, title: str):
        self._w()
        self._w("#" + "=" * 76)
        self._w(f"# {title}")
        self._w("#" + "=" * 76)

    def _sub_banner(self, title: str):
        self._w()
        self._w(f"# {'─' * 60}")
        self._w(f"# {title}")
        self._w(f"# {'─' * 60}")

    def _curl(self, method: str, endpoint: str,
              payload: Dict[str, Any], label: str = "request"):
        """Emit a curl call with response capture and check."""
        url      = f"${{BASE_URL}}{self.ZAPI}{endpoint}"
        body     = json.dumps(payload, separators=(",", ":"))
        # Escape single quotes for bash: ' → '\''
        body_esc = body.replace("'", r"'\''")
        self._w(f"RESP=$(curl \"${{CURL_OPTS[@]}}\" -X {method} \\")
        self._w(f"  '{url}' \\")
        self._w(f"  -d '{body_esc}')")
        self._w(f"check_response \"$RESP\" \"{label}\"")

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _write_header(self):
        self._w("#!/usr/bin/env bash")
        self._w("# ==========================================================================")
        self._w("# skudonet_apply.sh")
        self._w("# Generated by: ns_to_skudonet.py v1.0.0")
        self._w("# Source:       Citrix ADC (NetScaler) ns.conf")
        self._w("# Target:       Skudonet (ZEVENET) ZAPI v4.0")
        self._w("# ==========================================================================")
        self._w("#")
        self._w("# PREREQUISITES")
        self._w("# -------------")
        self._w("# 1. Export BASE_URL:  export BASE_URL=\"https://your-skudonet-host\"")
        self._w("# 2. Export API_KEY:   export API_KEY=\"your-api-key\"")
        self._w("# 3. Upload all SSL certificate PEM files to Skudonet before running.")
        self._w("# 4. Review all '# NOTE:' and '# MANUAL:' comments below.\")")
        self._w("#")
        self._w("# USAGE")
        self._w("# -----")
        self._w("#   bash skudonet_apply.sh")
        self._w("#   BASE_URL=https://10.0.0.1 API_KEY=mykey bash skudonet_apply.sh")
        self._w("#")
        self._w()
        self._w("set -uo pipefail")
        self._w()
        self._w(": \"${BASE_URL:?Please export BASE_URL}\"")
        self._w(": \"${API_KEY:?Please export API_KEY}\"")
        self._w()
        self._w("CURL_OPTS=(")
        self._w("  -sk")
        self._w("  -H \"ZAPI_KEY: ${API_KEY}\"")
        self._w("  -H 'Content-Type: application/json'")
        self._w("  --connect-timeout 10")
        self._w("  --max-time 30")
        self._w(")")
        self._w()
        self._w("# ---------------------------------------------------------------------------")
        self._w("# Helper: print result and optionally abort on error")
        self._w("# ---------------------------------------------------------------------------")
        self._w("ABORT_ON_ERROR=\"${ABORT_ON_ERROR:-0}\"  # set to 1 to stop on first error")
        self._w()
        self._w("check_response() {")
        self._w("  local resp=\"$1\" label=\"$2\"")
        self._w("  if echo \"$resp\" | grep -qE '\"error\"|\"description\":.*[Ee]rror'; then")
        self._w("    echo \"[FAIL] ${label}\"")
        self._w("    echo \"       ${resp}\" | head -c 300")
        self._w("    echo")
        self._w("    [[ \"$ABORT_ON_ERROR\" == \"1\" ]] && exit 1")
        self._w("  else")
        self._w("    echo \"[ OK ] ${label}\"")
        self._w("  fi")
        self._w("}")
        self._w()

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def _write_cert_section(self):
        if not self.mapper.certs:
            return

        self._banner("SSL CERTIFICATES")
        self._comment(
            "Upload certificates BEFORE creating farms that reference them."
        )
        self._comment(
            "Replace /path/to/ with actual paths on this machine or the Skudonet host."
        )
        self._w()

        for cert in self.mapper.certs:
            name      = cert["name"]
            cert_file = cert.get("cert_file") or "certificate.pem"
            key_file  = cert.get("key_file")  or "privatekey.pem"
            chain     = cert.get("linked_cert", "")

            self._sub_banner(f"Certificate: {name}")
            self._comment(f"  Cert file : {cert_file}")
            self._comment(f"  Key file  : {key_file}")
            if chain:
                self._comment(f"  Chain cert: {chain}")
            self._comment(
                f"  Type      : {cert.get('cert_type', 'SERVER')}"
            )
            self._w()
            self._comment("Uncomment and adjust paths to upload:")
            self._w(f"# RESP=$(curl \"${{CURL_OPTS[@]}}\" -X POST \\")
            self._w(f"#   '${{BASE_URL}}{self.ZAPI}/system/certificates' \\")
            self._w(f"#   -F 'file=@/path/to/{cert_file}' \\")
            self._w(f"#   -F 'key=@/path/to/{key_file}' \\")
            self._w(f"#   -F 'name={name}')")
            self._w(f"# check_response \"$RESP\" \"upload-cert-{name}\"")
            self._w()

    # ------------------------------------------------------------------
    # Farms
    # ------------------------------------------------------------------

    def _write_farms_section(self):
        self._banner("FARMS")
        for farm in self.mapper.farms:
            self._write_farm(farm)

    def _write_farm(self, farm: Dict[str, Any]):
        fname   = farm["farmname"]
        profile = farm["profile"]
        vip     = farm["vip"]
        vport   = farm["vport"]
        status  = farm.get("status", "up")
        ns_type = farm.get("_ns_type", "")
        ns_name = farm.get("_ns_name", fname)

        self._sub_banner(
            f"Farm: {fname}  |  profile={profile}  |  {vip}:{vport}  "
            f"|  NS: {ns_name} ({ns_type})"
        )

        if farm.get("_ns_comment"):
            self._comment(f"  NS comment: {farm['_ns_comment']}")

        for note in farm.get("_notes", []):
            self._comment(f"  NOTE: {note}")

        self._w()

        # ── 1. Create the farm ──────────────────────────────────────────
        self._comment("1. Create farm")
        self._curl(
            "POST", "/farms",
            {"farmname": fname, "profile": profile, "vip": vip, "vport": vport},
            label=f"create-farm-{fname}",
        )
        self._w()

        # ── 2. Configure farm settings ──────────────────────────────────
        self._comment("2. Configure farm settings")
        if profile == "http":
            self._configure_http_farm(farm)
        else:
            self._configure_l4xnat_farm(farm)

        # ── 3. SSL certificates ─────────────────────────────────────────
        ssl = farm.get("ssl", {})
        if ssl.get("certificates") or ssl.get("sni_certs"):
            self._comment("3. Bind SSL certificates")
            if ssl.get("_note_cipher"):
                self._comment(f"  CIPHER NOTE: {ssl['_note_cipher']}")
            if ssl.get("_note_profile"):
                self._comment(f"  PROFILE NOTE: {ssl['_note_profile']}")
            if ssl.get("_security_warning"):
                self._comment(f"  SECURITY WARNING: {ssl['_security_warning']}")
            for cert_name in ssl.get("certificates", []):
                self._curl(
                    "POST",
                    f"/farms/{fname}/certificates/{cert_name}",
                    {},
                    label=f"bind-cert-{cert_name}-to-{fname}",
                )
            for cert_name in ssl.get("sni_certs", []):
                self._comment(f"  SNI cert: {cert_name}")
                self._curl(
                    "POST",
                    f"/farms/{fname}/certificates/{cert_name}",
                    {"type": "sni"},
                    label=f"bind-sni-cert-{cert_name}-to-{fname}",
                )
            self._w()

        # ── 4. Services + backends ──────────────────────────────────────
        if profile == "http":
            self._comment("4. Services and backends")
            for svc in farm.get("services", []):
                self._write_service_http(fname, svc)
        else:
            self._comment("4. Backends (L4xNAT – backends attach directly to farm)")
            for be in farm.get("backends", []):
                self._write_backend_l4(fname, be)
            self._w()

        # ── 5. FarmGuardian ─────────────────────────────────────────────
        fgs = farm.get("farmguardian", [])
        if fgs:
            self._comment("5. FarmGuardian health check")
            for fg in fgs:
                self._write_farmguardian(fname, fg)

        # ── 6. Redirects (best-effort) ──────────────────────────────────
        redirects = farm.get("redirects", [])
        if redirects:
            self._comment("6. Redirects (converted from Responder policies)")
            for redir in redirects:
                self._write_redirect_comment(redir)

        # ── 7. Rewrite policies (manual review) ─────────────────────────
        rewrites = farm.get("rewrites", [])
        if rewrites:
            self._comment("7. Rewrite policies – MANUAL REVIEW REQUIRED")
            for rw in rewrites:
                self._write_rewrite_comment(rw)

        # ── 8. Start / stop ─────────────────────────────────────────────
        action = "start" if status == "up" else "stop"
        self._comment(f"8. {'Start' if action == 'start' else 'Stop'} farm")
        self._curl(
            "PUT", f"/farms/{fname}/actions",
            {"action": action},
            label=f"{action}-farm-{fname}",
        )
        self._w()

    # ------------------------------------------------------------------
    # Farm profile settings
    # ------------------------------------------------------------------

    def _configure_http_farm(self, farm: Dict[str, Any]):
        fname   = farm["farmname"]
        payload: Dict[str, Any] = {
            "algorithm": farm.get("algorithm", "weight"),
        }

        if farm.get("https_listener"):
            payload["listener"] = "https"
        else:
            payload["listener"] = "http"

        if farm.get("timeout"):
            payload["timeout"] = farm["timeout"]

        pers = farm.get("persistence", {})
        if pers.get("persistence"):
            payload["persistence"] = pers["persistence"]
            payload["ttl"]         = pers.get("ttl", 600)
            if pers.get("cookie"):
                payload["cookie"] = pers["cookie"]
            if pers.get("_note"):
                self._comment(f"  PERSISTENCE NOTE: {pers['_note']}")

        self._curl(
            "PUT", f"/farms/{fname}",
            payload,
            label=f"configure-http-farm-{fname}",
        )
        self._w()

    def _configure_l4xnat_farm(self, farm: Dict[str, Any]):
        fname   = farm["farmname"]
        payload: Dict[str, Any] = {
            "algorithm": farm.get("algorithm", "weight"),
            "nattype":   "dnat",
        }

        pers = farm.get("persistence", {})
        if pers.get("persistence"):
            payload["persistence"] = pers["persistence"]
            payload["ttl"]         = pers.get("ttl", 180)
            if pers.get("_note"):
                self._comment(f"  PERSISTENCE NOTE: {pers['_note']}")

        if farm.get("timeout"):
            payload["ttl"] = farm["timeout"]

        self._curl(
            "PUT", f"/farms/{fname}",
            payload,
            label=f"configure-l4xnat-farm-{fname}",
        )
        self._w()

    # ------------------------------------------------------------------
    # HTTP services
    # ------------------------------------------------------------------

    def _write_service_http(self, fname: str, svc: Dict[str, Any]):
        svc_id   = svc.get("id", "default")
        url_pat  = svc.get("urlp", "/")
        hostname = svc.get("hostheader", "")

        for note in svc.get("_notes", []):
            self._comment(f"  SERVICE NOTE ({svc_id}): {note}")

        svc_payload: Dict[str, Any] = {"id": svc_id}
        if url_pat and url_pat not in ("/", ""):
            svc_payload["urlp"] = url_pat
        if hostname:
            svc_payload["hostheader"] = hostname

        if svc.get("_ns_policy"):
            self._comment(
                f"  Service from CS policy '{svc.get('_ns_policy')}'"
                f"  [NS priority {svc.get('_ns_priority', '?')}]"
            )
            if svc.get("_ns_rule"):
                self._comment(f"  Original NS rule: {svc.get('_ns_rule')}")

        self._curl(
            "POST", f"/farms/{fname}/services",
            svc_payload,
            label=f"create-service-{fname}-{svc_id}",
        )
        self._w()

        # Backends of this service
        for be in svc.get("backends", []):
            self._write_backend_http(fname, svc_id, be)

        # Per-service FarmGuardian (if different from farm-level)
        svc_fg = svc.get("farmguardian")
        if svc_fg and svc_id != "default":
            self._comment(
                f"  NOTE: service '{svc_id}' has its own monitor "
                f"'{svc_fg.get('_ns_name', '')}' – "
                f"Skudonet supports one FarmGuardian per farm; "
                f"first one already applied at farm level"
            )

    def _write_backend_http(self, fname: str, svc_id: str,
                             be: Dict[str, Any]):
        ip     = be.get("ip", "")
        port   = be.get("port", 80)
        weight = be.get("weight", 1)
        status = be.get("status", "up")

        if not ip:
            self._comment("  WARNING: backend has no IP – skipping")
            return

        payload: Dict[str, Any] = {
            "ip":     ip,
            "port":   port,
            "weight": weight,
        }
        self._curl(
            "POST",
            f"/farms/{fname}/services/{svc_id}/backends",
            payload,
            label=f"add-backend-{fname}/{svc_id}-{ip}:{port}",
        )

        if status == "maintenance":
            self._comment(
                f"  Backend {ip}:{port} was DISABLED in NetScaler. "
                f"To set maintenance after creation:"
            )
            self._comment(
                f"  PUT {self.ZAPI}/farms/{fname}/services/{svc_id}"
                f"/backends/<ID> {{\"status\":\"maintenance\"}}"
            )

    def _write_backend_l4(self, fname: str, be: Dict[str, Any]):
        ip     = be.get("ip", "")
        port   = be.get("port", 0)
        weight = be.get("weight", 1)
        status = be.get("status", "up")

        if not ip:
            self._comment("  WARNING: backend has no IP – skipping")
            return

        payload: Dict[str, Any] = {
            "ip":     ip,
            "port":   port,
            "weight": weight,
        }
        self._curl(
            "POST",
            f"/farms/{fname}/backends",
            payload,
            label=f"add-backend-{fname}-{ip}:{port}",
        )

        if status == "maintenance":
            self._comment(
                f"  Backend {ip}:{port} was DISABLED in NetScaler – "
                f"set maintenance mode manually after creation"
            )

    # ------------------------------------------------------------------
    # FarmGuardian
    # ------------------------------------------------------------------

    def _write_farmguardian(self, fname: str, fg: Dict[str, Any]):
        self._comment(
            f"  NS Monitor: {fg.get('_ns_name','')}  "
            f"Type: {fg.get('_ns_type','')}"
        )
        payload: Dict[str, Any] = {
            "name":     fg["name"],
            "command":  fg["command"],
            "params":   fg["params"],
            "interval": fg.get("interval", 10),
            "log":      fg.get("log", True),
        }
        if fg.get("timeout"):
            payload["timeout"] = fg["timeout"]

        self._curl(
            "POST",
            f"/farms/{fname}/fg",
            payload,
            label=f"farmguardian-{fname}",
        )
        self._w()

    # ------------------------------------------------------------------
    # Redirect / Rewrite comment blocks
    # ------------------------------------------------------------------

    def _write_redirect_comment(self, redir: Dict[str, Any]):
        self._comment(f"  REDIRECT from NS responder policy '{redir.get('_ns_policy','')}':")
        self._comment(f"    NS rule  : {redir.get('_ns_rule','')}")
        self._comment(f"    URL      : {redir.get('redirect_url','')}")
        self._comment(f"    HTTP code: {redir.get('redirect_code', 302)}")
        self._comment(f"    {redir.get('_note','')}")
        self._comment(
            "  Configure this redirect in Skudonet HTTP farm settings "
            "or via the DirectiveRewrite module."
        )
        self._w()

    def _write_rewrite_comment(self, rw: Dict[str, Any]):
        rw_type = rw.get("type", "MANUAL_REVIEW")
        self._comment(f"  REWRITE [{rw_type}] from NS policy '{rw.get('_ns_policy','')}':")
        self._comment(f"    NS action  : {rw.get('_ns_action','')}")
        self._comment(f"    NS type    : {rw.get('_ns_type','')}")
        self._comment(f"    NS target  : {rw.get('_ns_target','')}")
        self._comment(f"    NS expr    : {rw.get('_ns_expr','')}")
        self._comment(f"    NS rule    : {rw.get('_ns_rule','')}")
        if rw.get("header_name"):
            self._comment(f"    Header name: {rw['header_name']}")
        if rw.get("header_value"):
            self._comment(f"    Header val : {rw['header_value']}")
        self._comment(f"    Note       : {rw.get('_note','')}")
        self._w()

    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------

    def _write_footer(self):
        self._banner("END OF GENERATED SCRIPT")
        self._w("echo")
        self._w("echo \"==========================================\"")
        self._w("echo \"Migration script completed.\"")
        self._w("echo \"Review any [FAIL] lines above.\"")
        self._w("echo \"Consult skudonet_config.json for manual_review_items.\"")
        self._w("echo \"==========================================\"")


###############################################################################
# SECTION 7 – Summary statistics
###############################################################################

def print_summary(
    model:        NetScalerModel,
    mapper:       SkudonetMapper,
    output_files: List[str],
    dry_run:      bool,
):
    """Print a human-readable migration summary to stdout."""

    total_backends = sum(
        len(be_list)
        for f in mapper.farms
        for svc in f.get("services", [])
        for be_list in [svc.get("backends", [])]
    ) + sum(
        len(f.get("backends", []))
        for f in mapper.farms
    )

    manual_count = len(mapper.manual_review)
    bar = "=" * 62

    print()
    print(bar)
    print("  NetScaler → Skudonet Migration Summary")
    print(bar)
    print()
    print("  Input (NetScaler entities parsed):")
    print(f"    LB vservers         : {len(model.lb_vservers)}")
    print(f"    CS vservers         : {len(model.cs_vservers)}")
    print(f"    Service groups      : {len(model.service_groups)}")
    print(f"    Services            : {len(model.services)}")
    print(f"    Servers             : {len(model.servers)}")
    print(f"    Monitors            : {len(model.monitors)}")
    print(f"    SSL certKeys        : {len(model.ssl_certkeys)}")
    print(f"    CS policies         : {len(model.cs_policies)}")
    print(f"    CS actions          : {len(model.cs_actions)}")
    print(f"    Responder policies  : {len(model.responder_policies)}")
    print(f"    Rewrite policies    : {len(model.rewrite_policies)}")
    print()
    print("  Output (Skudonet objects generated):")
    print(f"    Farms               : {len(mapper.farms)}")
    http_farms = sum(1 for f in mapper.farms if f.get("profile") == "http")
    l4_farms   = sum(1 for f in mapper.farms if f.get("profile") == "l4xnat")
    print(f"      HTTP farms        : {http_farms}")
    print(f"      L4xNAT farms      : {l4_farms}")
    total_svcs = sum(len(f.get("services", [])) for f in mapper.farms)
    print(f"    Services (HTTP)     : {total_svcs}")
    print(f"    Backends total      : {total_backends}")
    print(f"    Certificates        : {len(mapper.certs)}")
    total_fgs = sum(len(f.get("farmguardian", [])) for f in mapper.farms)
    print(f"    FarmGuardian checks : {total_fgs}")
    print()

    if manual_count:
        print(f"  ⚠  Items requiring MANUAL REVIEW ({manual_count}):")
        for item in mapper.manual_review[:25]:
            print(f"    • {item}")
        if manual_count > 25:
            print(f"    … and {manual_count - 25} more "
                  f"(see manual_review_items in skudonet_config.json)")
        print()

    if model.unhandled:
        unhandled_actual = [
            u for u in model.unhandled
            if not u.startswith("PARSE_ERROR")
        ]
        parse_errors = [
            u for u in model.unhandled
            if u.startswith("PARSE_ERROR")
        ]
        if unhandled_actual:
            shown    = unhandled_actual[:8]
            overflow = len(unhandled_actual) - len(shown)
            print(f"  ℹ  Unhandled NS commands ({len(unhandled_actual)} – "
                  f"likely VLAN/HA/GSLB or unsupported):")
            for u in shown:
                print(f"    • {u[:100]}")
            if overflow > 0:
                print(f"    … and {overflow} more")
            print()
        if parse_errors:
            print(f"  ✗  Parse errors ({len(parse_errors)}):")
            for e in parse_errors[:5]:
                print(f"    • {e[:120]}")
            print()

    if not dry_run and output_files:
        print("  Output files:")
        for fp in output_files:
            print(f"    {fp}")
        print()

    print(bar)


###############################################################################
# SECTION 8 – CLI / Main
###############################################################################

def build_arg_parser() -> argparse.ArgumentParser:
    desc = textwrap.dedent("""\
        Convert a Citrix ADC (NetScaler) ns.conf to Skudonet (ZEVENET)
        load balancer configuration.

        Output files (written to --output-dir):
          skudonet_config.json  - Structured JSON of all farms, services,
                                  backends, certificates, and health checks.
          skudonet_apply.sh     - bash script with curl calls to the
                                  Skudonet ZAPI v4.0 REST API.

        Skipped intentionally (assumed handled separately):
          - VLAN configuration
          - Floating IP / SNIP addresses
          - HA / cluster configuration
    """)

    parser = argparse.ArgumentParser(
        prog="ns_to_skudonet",
        description=desc,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "ns_conf",
        metavar="ns.conf",
        help="Path to the NetScaler ns.conf file",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        metavar="DIR",
        help="Directory for output files (default: current directory)",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Parse and report without writing any output files",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print verbose progress information",
    )
    parser.add_argument(
        "--api-format",
        choices=["bash", "powershell"],
        default="bash",
        help="Output format for API calls: bash (default) or powershell",
    )

    return parser


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    # ──────────────────────────────────────────────────────────────────
    # Validate input file
    # ──────────────────────────────────────────────────────────────────
    if not os.path.isfile(args.ns_conf):
        print(f"ERROR: File not found: {args.ns_conf}", file=sys.stderr)
        sys.exit(1)

    # ──────────────────────────────────────────────────────────────────
    # Prepare output directory
    # ──────────────────────────────────────────────────────────────────
    if not args.dry_run:
        os.makedirs(args.output_dir, exist_ok=True)

    # ──────────────────────────────────────────────────────────────────
    # Step 1: Parse ns.conf
    # ──────────────────────────────────────────────────────────────────
    print(f"[1/4] Parsing  →  {args.ns_conf}")
    ns_parser = NSConfigParser(args.ns_conf)
    try:
        ns_parser.load_and_parse()
    except OSError as exc:
        print(f"ERROR reading file: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"      {ns_parser._raw_line_count} raw lines, "
              f"{len(ns_parser.commands)} logical commands parsed.")

    # ──────────────────────────────────────────────────────────────────
    # Step 2: Build NetScaler model
    # ──────────────────────────────────────────────────────────────────
    print("[2/4] Building NetScaler model …")
    model = NetScalerModel()
    model.build(ns_parser.commands)

    if args.verbose:
        print(
            f"      Servers={len(model.servers)}  "
            f"ServiceGroups={len(model.service_groups)}  "
            f"LBvservers={len(model.lb_vservers)}  "
            f"CSvservers={len(model.cs_vservers)}  "
            f"Monitors={len(model.monitors)}  "
            f"CertKeys={len(model.ssl_certkeys)}"
        )

    # ──────────────────────────────────────────────────────────────────
    # Step 3: Map to Skudonet
    # ──────────────────────────────────────────────────────────────────
    print("[3/4] Mapping to Skudonet configuration …")
    mapper = SkudonetMapper(model)
    mapper.map()

    if args.verbose:
        print(
            f"      Farms={len(mapper.farms)}  "
            f"Certs={len(mapper.certs)}  "
            f"ManualReview={len(mapper.manual_review)}"
        )

    # ──────────────────────────────────────────────────────────────────
    # Step 4: Write output
    # ──────────────────────────────────────────────────────────────────
    output_files: List[str] = []

    if not args.dry_run:
        print(f"[4/4] Writing output to  →  {os.path.abspath(args.output_dir)}")

        json_path = SkudonetConfigWriter(mapper, args.output_dir).write()
        sh_path   = SkudonetAPIScriptWriter(mapper, args.output_dir).write()
        output_files = [json_path, sh_path]

        if args.verbose:
            print(f"      JSON: {json_path}")
            print(f"      SH:   {sh_path}")
    else:
        print("[4/4] Dry run – no files written.")

    # ──────────────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────────────
    print_summary(model, mapper, output_files, args.dry_run)


if __name__ == "__main__":
    main()
