# SDN---Docker
# Projet-Cloud-CDSI - SDN sécurisé (Mininet + POX + ML)

## Objectif
Environnement Dockerisé pour simuler deux sous-réseaux connectés par un routeur (Mininet),
contrôlé par POX. POX détecte les attaques (heuristiques + ML via detector service)
et applique des `flow_mod` OpenFlow pour mitigation.

## Quickstart
1. git init, add files
2. docker compose build
3. docker compose up -d
4. docker exec -it mininet-sim bash
5. python3 /topologies/network_topology_l3.py
6. Dans Mininet CLI : vérifier connectivité & exécuter attaques:
   - h6 python3 /topologies/scripts/dos_attack.py 10.0.1.10 8080
   - h6 python3 /topologies/scripts/arp_spoof.py 10.0.1.10

## Tests
- Observer logs POX: `docker logs -f pox-controller`
- Vérifier flows: dans Mininet shell `sh ovs-ofctl dump-flows s1`
- Interagir avec detector: `curl -X POST http://172.20.100.20:8000/predict -d '{"src_mac":"00:00:00:00:02:03","pkt_count":1500,"byte_count":1000000,"duration":10,"arp_count":20,"packet_in_rate":300}' -H "Content-Type: application/json"`

## Versionning (Git)
Commit étape par étape :
git init
git add .
git commit -m "Initial project scaffolding: docker-compose, pox, mininet, detector"
