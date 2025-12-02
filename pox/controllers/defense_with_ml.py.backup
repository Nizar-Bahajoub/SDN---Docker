# pox/controllers/defense_with_ml.py
from pox.core import core
from pox.lib.packet import ethernet
import pox.openflow.libopenflow_01 as of
import time, requests, os
from collections import defaultdict

log = core.getLogger()

DETECTOR_URL = os.getenv('DETECTOR_URL', 'http://172.20.100.20:8000/predict')
DETECTOR_TIMEOUT = float(os.getenv('DETECTOR_TIMEOUT', '2.0'))
ARP_RATE_WINDOW = 3.0
ARP_RATE_THRESHOLD = 30
PKT_IN_RATE_WINDOW = 2.0
PKT_IN_RATE_THRESHOLD = 400

class DefenseController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.mac_stats = defaultdict(lambda: {'arp_count':0, 'arp_ts':time.time(), 'pktin_count':0, 'pktin_ts':time.time(),
                                              'pkt_total':0, 'byte_total':0})
        self.mac_bindings = {}
        self.blocked_macs = set()
        log.warning("POX Defense controller ready")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", event.connection.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        dpid = event.connection.dpid
        in_port = event.port
        src = str(packet.src)
        dst = str(packet.dst)

        # learning
        self.mac_bindings.setdefault(dpid, {})[src] = in_port

        # update stats
        st = self.mac_stats[src]
        now = time.time()
        st['pkt_total'] += 1
        st['byte_total'] += len(event.ofp.data)

        if packet.type == ethernet.ARP_TYPE:
            if now - st['arp_ts'] > ARP_RATE_WINDOW:
                st['arp_count'] = 1
                st['arp_ts'] = now
            else:
                st['arp_count'] += 1
            if st['arp_count'] > ARP_RATE_THRESHOLD:
                log.warn("High ARP rate from %s -> installing drop flows", src)
                self._install_block_flow(src)
                return

        if now - st['pktin_ts'] > PKT_IN_RATE_WINDOW:
            st['pktin_count'] = 1
            st['pktin_ts'] = now
        else:
            st['pktin_count'] += 1
            if st['pktin_count'] > PKT_IN_RATE_THRESHOLD:
                log.warn("High PacketIn rate from %s -> querying detector", src)
                features = {
                    "src_mac": src,
                    "pkt_count": st['pkt_total'],
                    "byte_count": st['byte_total'],
                    "duration": now - st['pktin_ts'],
                    "arp_count": st['arp_count'],
                    "packet_in_rate": st['pktin_count']
                }
                verdict, score = self._query_detector(features)
                if verdict == 'attack':
                    self._install_block_flow(src)
                    return

        out_port = self._get_out_port(dpid, dst)
        if out_port == of.OFPP_FLOOD:
            msg = of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
        else:
            fm = of.ofp_flow_mod()
            fm.match.dl_dst = packet.dst
            fm.priority = 100
            fm.idle_timeout = 30
            fm.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(fm)
            event.connection.send(of.ofp_packet_out(data=event.ofp, action=of.ofp_action_output(port=out_port)))

    def _get_out_port(self, dpid, dst):
        if dpid in self.mac_bindings and dst in self.mac_bindings[dpid]:
            return self.mac_bindings[dpid][dst]
        return of.OFPP_FLOOD

    def _install_block_flow(self, src_mac):
        if src_mac in self.blocked_macs:
            return
        self.blocked_macs.add(src_mac)
        for con in core.openflow.connections:
            msg = of.ofp_flow_mod()
            msg.match.dl_src = src_mac
            msg.priority = 99999
            msg.actions = []
            con.send(msg)
        log.info("Installed drop flows for %s on all switches", src_mac)

    def _query_detector(self, features):
        try:
            resp = requests.post(DETECTOR_URL, json=features, timeout=DETECTOR_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                return data.get('verdict','benign'), data.get('score',0.0)
            else:
                log.warn("Detector returned status %s", resp.status_code)
                return 'benign', 0.0
        except Exception as e:
            log.error("Detector request failed: %s", e)
            return 'benign', 0.0

def launch():
    core.registerNew(DefenseController)
