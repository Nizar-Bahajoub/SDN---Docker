# pox/controllers/defense_with_ml.py
"""
POX Defense controller — intégration :
- learning L2
- détection ML (local joblib ou remote REST)
- mitigation (install drop flows)
- protections anti-spoof / port-security / router-lock
- authentification POX -> detector via token (Authorization: Bearer ...)
Configuration via variables d'environnement.
"""

from pox.core import core
from pox.lib.packet import ethernet, arp
import pox.openflow.libopenflow_01 as of
from collections import defaultdict
import time, os, threading, traceback
import requests

log = core.getLogger()

# -----------------------
# Configuration
# -----------------------
DETECTOR_URL = os.getenv('DETECTOR_URL', 'http://172.20.100.20:8000/predict')
DETECTOR_TIMEOUT = float(os.getenv('DETECTOR_TIMEOUT', '2.0'))
DETECTOR_SECRET = os.getenv('DETECTOR_SECRET', '')  # if set, will be used as Bearer token

# Local model
LOCAL_MODEL_PATH = os.getenv('LOCAL_MODEL_PATH', '/pox/models/model.pkl')
LOCAL_MODEL_THRESHOLD = float(os.getenv('LOCAL_MODEL_THRESHOLD', '0.5'))

# Anti-spoof / port-security
PORT_LOCKING = False #os.getenv('PORT_LOCKING', 'true').lower() in ('1','true','yes')
MAC_MOVE_BLOCK = False #os.getenv('MAC_MOVE_BLOCK', 'true').lower() in ('1','true','yes')
ROUTER_MAC = os.getenv('ROUTER_MAC', '')  # ex: "00:00:00:00:00:01"
ROUTER_AUTO_LEARN = os.getenv('ROUTER_AUTO_LEARN', 'true').lower() in ('1','true','yes')

# thresholds
ARP_RATE_WINDOW = float(os.getenv('ARP_RATE_WINDOW', '3.0'))
ARP_RATE_THRESHOLD = int(os.getenv('ARP_RATE_THRESHOLD', '30'))
PKT_IN_RATE_WINDOW = float(os.getenv('PKT_IN_RATE_WINDOW', '2.0'))
PKT_IN_RATE_THRESHOLD = int(os.getenv('PKT_IN_RATE_THRESHOLD', '400'))

# ------------------------------------------------------------------
# Try load a local joblib model (optional). Use predict_proba if available
# ------------------------------------------------------------------
model = None
use_local_model = False
try:
    if os.path.exists(LOCAL_MODEL_PATH):
        import joblib, numpy as np
        model = joblib.load(LOCAL_MODEL_PATH)
        use_local_model = True
        log.info("Loaded local ML model from %s", LOCAL_MODEL_PATH)
    else:
        log.info("No local model at %s — will use remote detector if available", LOCAL_MODEL_PATH)
except Exception as e:
    log.error("Failed to load local model: %s", e)
    use_local_model = False
    model = None


class DefenseController(object):
    def __init__(self):
        core.openflow.addListeners(self)

        # stats per MAC
        self.mac_stats = defaultdict(lambda: {
            'arp_count': 0, 'arp_ts': time.time(),
            'pktin_count': 0, 'pktin_ts': time.time(),
            'pkt_total': 0, 'byte_total': 0,
            'first_seen': time.time()
        })
        # port binding: dpid -> mac -> port
        self.mac_bindings = defaultdict(dict)
        # reverse binding: dpid -> port -> set(mac)
        self.port_bindings = defaultdict(dict)
        # blocked MACs
        self.blocked_macs = set()
        # router mac -> (dpid, port) mapping when learned
        self.router_binding = None

        log.warning(
            "POX Defense controller ready (ML mode: %s, token:%s)",
            "local" if use_local_model else "remote",
            "set" if DETECTOR_SECRET else "none"
        )

    # -----------------------
    # OpenFlow events
    # -----------------------
    def _handle_ConnectionUp(self, event):
        dpid = event.connection.dpid
        log.info("Switch %s connected", dpid)

        # Optionnel : règle permissive par défaut (L2 learning gère ensuite)
        # fm = of.ofp_flow_mod()
        # fm.priority = 1
        # fm.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        # event.connection.send(fm)
        # log.info("Default ALLOW rule installed on switch %s", dpid)

    def _handle_PacketIn(self, event):
        try:
            packet = event.parsed
            if not packet or not packet.parsed:
                return

            dpid = event.connection.dpid
            in_port = event.port
            src = str(packet.src)
            dst = str(packet.dst)
            now = time.time()

            # 1) Si MAC déjà bloquée -> drop immédiat
            if src in self.blocked_macs:
                log.debug("PacketIn from blocked MAC %s — dropping", src)
                self._install_block_flow_on_conn(src, event.connection)
                return

            # 2) Port security (non bloquante sur trafic normal)
            self._enforce_port_security(dpid, in_port, src)

            # 3) L2 learning simple
            self.mac_bindings[dpid][src] = in_port
            self.port_bindings[dpid].setdefault(in_port, set()).add(src)

            # 4) Stats
            st = self.mac_stats[src]
            st['pkt_total'] += 1
            st['byte_total'] += (len(event.ofp.data) if event.ofp and event.ofp.data else 0)

            # --------- ARP handling & anti-spoof ----------
            if packet.type == ethernet.ARP_TYPE:
                if now - st.get('arp_ts', 0) > ARP_RATE_WINDOW:
                    st['arp_count'] = 1
                    st['arp_ts'] = now
                else:
                    st['arp_count'] += 1

                if st['arp_count'] > ARP_RATE_THRESHOLD:
                    log.warn("High ARP rate from %s -> installing drop flows", src)
                    self._install_block_flow(src)
                    return

                # inspection ARP + router-lock
                try:
                    arp_pkt = packet.next
                    if arp_pkt and hasattr(arp_pkt, 'protosrc') and hasattr(arp_pkt, 'protdst'):
                        if ROUTER_MAC:
                            if str(packet.src) == ROUTER_MAC and not self._is_from_router_port(dpid, in_port, ROUTER_MAC):
                                log.warn("ARP from rogue source claiming ROUTER_MAC %s -> blocking %s",
                                         ROUTER_MAC, src)
                                self._install_block_flow(src)
                                return
                except Exception:
                    log.debug("ARP inspection error", exc_info=True)

            # --------- PacketIn rate ----------
            if now - st.get('pktin_ts', 0) > PKT_IN_RATE_WINDOW:
                st['pktin_count'] = 1
                st['pktin_ts'] = now
            else:
                st['pktin_count'] += 1

            if st['pktin_count'] > PKT_IN_RATE_THRESHOLD:
                features = {
                    "src_mac": src,
                    "pkt_count": st['pkt_total'],
                    "byte_count": st['byte_total'],
                    "duration": now - st.get('first_seen', now),
                    "arp_count": st['arp_count'],
                    "packet_in_rate": st['pktin_count']
                }
                t = threading.Thread(target=self._evaluate_and_mitigate, args=(features,))
                t.daemon = True
                t.start()

            # --------- Forwarding L2 ----------
            out_port = self._get_out_port(dpid, dst)
            if out_port == of.OFPP_FLOOD:
                msg = of.ofp_packet_out(
                    data=event.ofp,
                    action=of.ofp_action_output(port=of.OFPP_FLOOD)
                )
                event.connection.send(msg)
            else:
                fm = of.ofp_flow_mod()
                fm.match.dl_dst = packet.dst
                fm.priority = 100
                fm.idle_timeout = 30
                fm.actions.append(of.ofp_action_output(port=out_port))
                event.connection.send(fm)
                event.connection.send(of.ofp_packet_out(
                    data=event.ofp,
                    action=of.ofp_action_output(port=out_port)
                ))

            # --------- Router auto-learn ----------
            if ROUTER_AUTO_LEARN and ROUTER_MAC and src == ROUTER_MAC and not self.router_binding:
                self.router_binding = (dpid, in_port)
                log.info("Router auto-learned: MAC=%s at switch=%s port=%s",
                         ROUTER_MAC, dpid, in_port)

        except Exception as e:
            log.error("Exception in PacketIn handler: %s", e)
            log.debug(traceback.format_exc())

    # -----------------------
    # Helpers
    # -----------------------
    def _get_out_port(self, dpid, dst):
        if dpid in self.mac_bindings and dst in self.mac_bindings[dpid]:
            return self.mac_bindings[dpid][dst]
        return of.OFPP_FLOOD

    def _install_block_flow(self, src_mac):
        """Install drop flow for src_mac on all switches (global block)."""
        if src_mac in self.blocked_macs:
            return
        self.blocked_macs.add(src_mac)

        for conn in core.openflow.connections:
            try:
                msg = of.ofp_flow_mod()
                msg.match.dl_src = src_mac
                msg.priority = 99999
                msg.actions = []  # empty => drop
                conn.send(msg)
            except Exception as e:
                log.error("Failed to send flow_mod to switch %s: %s",
                          getattr(conn, 'dpid', '?'), e)
        log.info("Installed drop flows for %s on all switches", src_mac)

    def _install_block_flow_on_conn(self, src_mac, connection):
        """Install drop flow on a single connection (switch)."""
        try:
            msg = of.ofp_flow_mod()
            msg.match.dl_src = src_mac
            msg.priority = 99999
            msg.actions = []
            connection.send(msg)
            log.debug("Installed drop flow for %s on switch %s",
                      src_mac, connection.dpid)
        except Exception as e:
            log.error("Failed to install single-switch drop flow: %s", e)

    def _evaluate_and_mitigate(self, features):
        src = features.get('src_mac')
        if not src or src in self.blocked_macs:
            return

        # 1) Local model
        try:
            if use_local_model and model is not None:
                import numpy as np
                vec = np.array([[features.get('pkt_count', 0),
                                 features.get('byte_count', 0),
                                 features.get('duration', 0.0),
                                 features.get('arp_count', 0),
                                 features.get('packet_in_rate', 0)]])
                try:
                    if hasattr(model, "predict_proba"):
                        proba = float(model.predict_proba(vec)[0][1])
                    else:
                        pred = model.predict(vec)
                        proba = 1.0 if pred[0] == 1 else 0.0
                    log.info("Local model proba for %s = %.3f", src, proba)
                    if proba >= LOCAL_MODEL_THRESHOLD:
                        log.warn("Local model: blocking %s (score=%.3f)", src, proba)
                        self._install_block_flow(src)
                        return
                except Exception as e:
                    log.error("Local model predict error: %s", e)
        except Exception:
            log.debug("Local model evaluation error", exc_info=True)

        # 2) Remote detector
        if DETECTOR_URL:
            try:
                headers = {}
                if DETECTOR_SECRET:
                    headers['Authorization'] = f"Bearer {DETECTOR_SECRET}"
                resp = requests.post(
                    DETECTOR_URL,
                    json=features,
                    timeout=DETECTOR_TIMEOUT,
                    headers=headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    verdict = data.get('verdict', 'benign')
                    score = float(data.get('score', 0.0))
                    log.info("Remote detector verdict for %s = %s (score=%.3f)",
                             src, verdict, score)
                    if verdict == 'attack' or score >= 0.5:
                        log.warn("Remote detector: blocking %s", src)
                        self._install_block_flow(src)
                        return
                else:
                    log.warn("Detector returned status %s", resp.status_code)
            except Exception as e:
                log.error("Detector request failed: %s", e)

        # 3) Heuristiques finales
        if features.get('packet_in_rate', 0) > (PKT_IN_RATE_THRESHOLD * 3):
            log.warn("Heuristic extreme rate: blocking %s", src)
            self._install_block_flow(src)
            return
        if features.get('arp_count', 0) > (ARP_RATE_THRESHOLD * 2):
            log.warn("Heuristic extreme ARP: blocking %s", src)
            self._install_block_flow(src)
            return

    # -----------------------
    # Port security / anti-mac-move
    # -----------------------
    def _enforce_port_security(self, dpid, port, mac):
        if not PORT_LOCKING:
            return

        m = mac.lower()

        # ignorer broadcast/multicast (LLDP, IPv6, etc.)
        if m == "ff:ff:ff:ff:ff:ff":
            return
        if m.startswith("01:") or m.startswith("33:33"):
            return

        existing = self.port_bindings[dpid].get(port)
        if existing:
            if mac in existing:
                return
            # ne pas bloquer agressivement, juste log + ignorer
            log.info(
                "Port %s:%s already has MACs %s, ignoring new MAC %s (no block)",
                dpid, port, existing, mac
            )
            return
        else:
            self.port_bindings[dpid][port] = set([mac])
            log.debug("Port security: learned MAC %s on switch %s port %s",
                      mac, dpid, port)

    def _is_from_router_port(self, dpid, port, mac):
        """Return True if this (dpid,port) matches the router binding (if known)."""
        if not mac:
            return False
        if self.router_binding:
            rb_dpid, rb_port = self.router_binding
            return (dpid == rb_dpid and port == rb_port)
        return False  # pas encore appris


def launch():
    core.registerNew(DefenseController)
