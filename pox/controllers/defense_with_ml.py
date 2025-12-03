# pox/controllers/defense_with_ml.py
"""
POX Defense controller — version CLEAN :
- L2 learning stable
- Détection ML (local ou REST)
- Mitigation propre (drop flows)
- Port-security amélioré + uplink whitelist
- Logs propres : uniquement décisions importantes
"""

from pox.core import core
from pox.lib.packet import ethernet, arp
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of
from collections import defaultdict
import time, os, threading, traceback
import requests
import logging

log = core.getLogger()

# -----------------------
# Configuration
# -----------------------
DETECTOR_URL = os.getenv('DETECTOR_URL', 'http://172.20.100.20:8000/predict')
DETECTOR_TIMEOUT = float(os.getenv('DETECTOR_TIMEOUT', '2.0'))
DETECTOR_SECRET = os.getenv('DETECTOR_SECRET', '')

LOCAL_MODEL_PATH = os.getenv('LOCAL_MODEL_PATH', '/pox/models/model.pkl')
LOCAL_MODEL_THRESHOLD = float(os.getenv('LOCAL_MODEL_THRESHOLD', '0.5'))

PORT_LOCKING = os.getenv('PORT_LOCKING', 'true').lower() in ('1','true','yes')
MAC_MOVE_BLOCK = os.getenv('MAC_MOVE_BLOCK', 'true').lower() in ('1','true','yes')
ROUTER_MAC = os.getenv('ROUTER_MAC', '')

ROUTER_AUTO_LEARN = os.getenv('ROUTER_AUTO_LEARN', 'true').lower() in ('1','true','yes')

PROTECTED_MACS = set()
if os.getenv('PROTECTED_MACS'):
    for m in os.getenv('PROTECTED_MACS').split(','):
        PROTECTED_MACS.add(m.strip().lower())

# IMPORTANT : définir les ports uplink
# Exemple : port 1 est le lien inter-switch → port-security désactivé
UPLINK_PORTS = {1}

# Rate thresholds
ARP_RATE_WINDOW = 3.0
ARP_RATE_THRESHOLD = 30
PKT_IN_RATE_WINDOW = 2.0
PKT_IN_RATE_THRESHOLD = 400

# ML cache
DETECTOR_CACHE_TTL = 10
DETECTOR_MIN_QUERY_INTERVAL = 1.0

# ----------------------------
# Load local joblib model (optional)
# ----------------------------
model = None
use_local_model = False
try:
    import joblib
    if os.path.exists(LOCAL_MODEL_PATH):
        model = joblib.load(LOCAL_MODEL_PATH)
        use_local_model = True
        log.info("[ML] Local model loaded.")
    else:
        log.info("[ML] No local model — using remote detector.")
except Exception as e:
    log.error("[ML] Failed to load local model: %s", e)


# -----------------------
# DefenseController FINAL ADJUSTED
# -----------------------

class DefenseController(object):
    def __init__(self):
        core.openflow.addListeners(self)

        self.mac_stats = defaultdict(lambda: {
            'arp_count': 0, 'arp_ts': time.time(),
            'pktin_count': 0, 'pktin_ts': time.time(),
            'pkt_total': 0, 'byte_total': 0,
            'first_seen': time.time()
        })

        self.mac_bindings = defaultdict(dict)
        self.port_bindings = defaultdict(dict)
        self.blocked_macs = set()
        self.router_binding = None

        # ⚡ Anti-spam ML
        self.last_query_ts = defaultdict(lambda: 0.0)
        self.verdict_cache = {}
        self.ml_lock = defaultdict(threading.Lock)  # lock par MAC pour éviter threads multiples

        log.warning("=== POX Defense Controller READY ===")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", event.connection.dpid)

    def _handle_PacketIn(self, event):
        try:
            packet = event.parsed
            if not packet:
                return

            dpid = event.connection.dpid
            in_port = event.port
            src = str(packet.src).lower()
            dst = str(packet.dst).lower()
            now = time.time()

            # ⚡ Ignore déjà bloqués
            if src in self.blocked_macs:
                return

            # Port-security
            if PORT_LOCKING and in_port not in UPLINK_PORTS:
                self._port_security(dpid, in_port, src)

            # Learning
            self.mac_bindings[dpid][src] = in_port

            # Stats
            st = self.mac_stats[src]
            st['pkt_total'] += 1
            st['byte_total'] += len(event.ofp.data) if event.ofp and event.ofp.data else 0

            # ARP handling
            if packet.type == ethernet.ARP_TYPE:
                self._handle_arp(src, dpid, in_port, st)

            # Rate → ML
            if self._update_pktin_rate(st, now):
                features = {
                    "src_mac": src,
                    "pkt_count": st['pkt_total'],
                    "byte_count": st['byte_total'],
                    "duration": now - st['first_seen'],
                    "arp_count": st['arp_count'],
                    "packet_in_rate": st['pktin_count'],
                    "dpid": dpid,
                    "in_port": in_port
                }
                # ⚡ Thread unique par hôte
                if not self.ml_lock[src].locked():
                    threading.Thread(target=self._evaluate_and_mitigate,
                                     args=(features,), daemon=True).start()

            # L2 forwarding
            out = self.mac_bindings[dpid].get(dst, of.OFPP_FLOOD)
            msg = of.ofp_packet_out(data=event.ofp,
                                    action=of.ofp_action_output(port=out))
            event.connection.send(msg)

        except Exception as e:
            log.error("PacketIn error: %s", e)
            log.debug(traceback.format_exc())

    def _handle_arp(self, src, dpid, port, st):
        now = time.time()
        if now - st['arp_ts'] > ARP_RATE_WINDOW:
            st['arp_count'] = 1
            st['arp_ts'] = now
        else:
            st['arp_count'] += 1

        if st['arp_count'] > ARP_RATE_THRESHOLD:
            log.warning("[ARP] High rate → block %s", src)
            self._install_block(src)

    def _update_pktin_rate(self, st, now):
        if now - st['pktin_ts'] > PKT_IN_RATE_WINDOW:
            st['pktin_count'] = 1
            st['pktin_ts'] = now
        else:
            st['pktin_count'] += 1
        return st['pktin_count'] > PKT_IN_RATE_THRESHOLD

    def _evaluate_and_mitigate(self, features):
        src = features['src_mac']
        with self.ml_lock[src]:
            if src in self.blocked_macs:
                return

            now = time.time()

            # Local ML
            if use_local_model and model:
                try:
                    import numpy as np
                    vec = np.array([[features["pkt_count"], features["byte_count"],
                                     features["duration"], features["arp_count"],
                                     features["packet_in_rate"]]])
                    proba = model.predict_proba(vec)[0][1]
                    if proba >= LOCAL_MODEL_THRESHOLD:
                        log.warning("[ML-LOCAL] ATTACK %s (%.3f)", src, proba)
                        self._install_block(src)
                        return
                except Exception:
                    log.debug("[ML-LOCAL] Failed local prediction for %s", src)

            # Cache
            cache = self.verdict_cache.get(src)
            if cache and cache[1] > now:
                verdict, _, score = cache
                if verdict == "attack":
                    log.warning("[ML-CACHE] ATTACK %s (%.3f)", src, score)
                    self._install_block(src)
                return

            # Remote ML
            if DETECTOR_URL and now - self.last_query_ts[src] > DETECTOR_MIN_QUERY_INTERVAL:
                try:
                    headers = {}
                    if DETECTOR_SECRET:
                        headers["Authorization"] = f"Bearer {DETECTOR_SECRET}"
                    resp = requests.post(DETECTOR_URL, json=features,
                                         timeout=DETECTOR_TIMEOUT, headers=headers)
                    self.last_query_ts[src] = now

                    if resp.status_code == 200:
                        data = resp.json()
                        verdict = data.get("verdict", "benign")
                        score = float(data.get("score", 0.0))
                        self.verdict_cache[src] = (verdict, now + DETECTOR_CACHE_TTL, score)

                        log.info("[ML-REMOTE] %s → %s (%.3f)", src, verdict, score)
                        if verdict == "attack":
                            log.warning("[ML-REMOTE] BLOCK %s", src)
                            self._install_block(src)
                except Exception:
                    log.error("[ML-REMOTE] Error querying detector for %s", src)

    def _port_security(self, dpid, port, mac):
        if port in UPLINK_PORTS:
            return
        existing = self.port_bindings[dpid].get(port)
        if existing and mac not in existing:
            log.info("[PORT-SEC] Switch %s port %s already has %s", dpid, port, existing)
            return
        self.port_bindings[dpid].setdefault(port, set()).add(mac)

    def _install_block(self, mac):
        if mac in self.blocked_macs or mac in PROTECTED_MACS:
            return
        self.blocked_macs.add(mac)

        for conn in core.openflow.connections:
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(mac)
            msg.priority = 99999
            msg.actions = []  # drop
            conn.send(msg)

        log.warning("[BLOCK] Installed drop flow for %s", mac)


def launch():
    core.getLogger().setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    core.registerNew(DefenseController)
