#!/usr/bin/env python3
import socket
import ipaddress
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

ASN_MAP = {
    'AS8075': {'org': 'Microsoft', 'type': 'Cloud Server'},
    'AS15169': {'org': 'Google', 'type': 'Web Service'},
    'AS16509': {'org': 'Amazon AWS', 'type': 'Cloud Server'},
    'AS13335': {'org': 'Cloudflare', 'type': 'CDN'},
    'AS32934': {'org': 'Facebook/Meta', 'type': 'Social Media'},
}

KNOWN_CIDRS = {
    'Microsoft Azure': [
        '13.64.0.0/11', '13.104.0.0/14', '20.36.0.0/14', '40.64.0.0/10',
        '51.104.0.0/14', '52.96.0.0/12', '104.40.0.0/13'
    ],
    'Amazon AWS': [
        '3.0.0.0/8', '13.32.0.0/11', '18.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8'
    ],
    'Google': [
        '8.8.8.0/24', '8.34.208.0/20', '34.0.0.0/8', '35.0.0.0/8'
    ],
    'Cloudflare': [
        '1.1.1.0/24', '1.0.0.0/24', '104.16.0.0/12', '172.64.0.0/13'
    ]
}

HIGH_RISK_PORTS = {22, 23, 2323, 3389, 5900}


def get_ip_info(ip: str) -> Dict[str, str]:
    info = {
        'ip': ip,
        'type': 'Unknown',
        'organization': 'Unknown',
        'is_private': False,
        'is_reserved': False,
        'hostname': None,
        'asn': None,
        'description': 'External host',
        'risk_level': 'medium'
    }

    if not ip:
        return info

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return info

    if addr.is_private:
        info.update({
            'is_private': True,
            'type': 'Local Network',
            'organization': 'Private Address Space',
            'description': 'Private RFC1918 address',
            'risk_level': 'safe'
        })
        return info

    if addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
        info.update({
            'is_reserved': True,
            'type': 'Special Use',
            'organization': 'IANA Reserved',
            'description': 'Non-routable or special-purpose IP',
            'risk_level': 'safe'
        })
        return info

    enrich_by_cidr(ip, info)

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        info['hostname'] = hostname
        enrich_by_hostname(hostname, info)
    except Exception:
        pass

    if info['organization'] == 'Unknown':
        info['risk_level'] = 'medium'
    else:
        info['risk_level'] = 'safe'

    return info


def enrich_by_cidr(ip: str, info: Dict[str, str]) -> None:
    ip_obj = ipaddress.ip_address(ip)

    for org, cidrs in KNOWN_CIDRS.items():
        for cidr in cidrs:
            if ip_obj in ipaddress.ip_network(cidr):
                info['organization'] = org
                info['type'] = 'Cloud / Service Provider'
                info['description'] = f'{org} infrastructure'
                info['risk_level'] = 'safe'
                return


def enrich_by_hostname(hostname: str, info: Dict[str, str]) -> None:
    h = hostname.lower()

    if any(k in h for k in ['azure', 'cloudapp', 'windows']):
        info.update({'organization': 'Microsoft', 'type': 'Cloud Service'})
    elif any(k in h for k in ['amazonaws', 'compute', 'ec2']):
        info.update({'organization': 'Amazon AWS', 'type': 'Cloud Service'})
    elif any(k in h for k in ['google', 'gstatic', '1e100']):
        info.update({'organization': 'Google', 'type': 'Web Service'})
    elif any(k in h for k in ['cloudflare', 'cf-ip']):
        info.update({'organization': 'Cloudflare', 'type': 'CDN'})
    elif any(k in h for k in ['facebook', 'fbcdn', 'whatsapp']):
        info.update({'organization': 'Meta', 'type': 'Social Media'})


def assess_connection_risk(ip_info: Dict[str, str], port: int | None = None) -> Dict[str, str]:
    level = ip_info.get('risk_level', 'medium')

    if port in HIGH_RISK_PORTS and not ip_info.get('is_private'):
        level = 'high'

    mapping = {
        'safe': ('success', '✅', 'Known trusted infrastructure'),
        'medium': ('warning', '⚠️', 'Unclassified external host'),
        'high': ('danger', '🚨', 'Potential attack surface'),
    }

    color, icon, message = mapping.get(level, ('info', 'ℹ️', 'Unknown'))

    return {
        'level': level,
        'color': color,
        'icon': icon,
        'message': message
    }


def analyze_traffic_summary(top_ips: List[Tuple[str, int]]) -> Dict:
    summary = {
        'total_ips': len(top_ips),
        'local_ips': 0,
        'external_ips': 0,
        'organizations': {},
        'service_types': {},
        'risk_summary': {'safe': 0, 'medium': 0, 'high': 0}
    }

    for ip, count in top_ips:
        info = get_ip_info(ip)

        if info['is_private']:
            summary['local_ips'] += 1
        else:
            summary['external_ips'] += 1

        org = info['organization']
        summary['organizations'][org] = summary['organizations'].get(org, 0) + count

        st = info['type']
        summary['service_types'][st] = summary['service_types'].get(st, 0) + count

        rl = info['risk_level']
        summary['risk_summary'][rl] = summary['risk_summary'].get(rl, 0) + 1

    return summary
