#!/usr/bin/env python3
"""
Complete DNS Resolver Analysis for Assignment 2 Part E
- Real-time URL-by-URL status display
- All required metrics and graphs
"""

import socket
import struct
import time
import json
import os
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')


class DNSCache:
    """DNS Cache with TTL support and statistics tracking"""
    def __init__(self):
        self.iterative_cache = {'root': {}, 'tld': {}, 'auth': {}}
        self.recursive_cache = {}
        self.stats = {
            'recursive_hits': 0,
            'recursive_misses': 0,
            'iterative_hits': 0,
            'iterative_misses': 0,
            'total_queries': 0
        }

    def get_recursive(self, domain):
        self.stats['total_queries'] += 1
        entry = self.recursive_cache.get(domain)
        if entry and datetime.now() < entry['expires']:
            self.stats['recursive_hits'] += 1
            return entry['ip']
        elif entry:
            del self.recursive_cache[domain]
        self.stats['recursive_misses'] += 1
        return None

    def set_recursive(self, domain, ip, ttl=300):
        self.recursive_cache[domain] = {
            'ip': ip,
            'expires': datetime.now() + timedelta(seconds=ttl),
            'cached_at': datetime.now().isoformat()
        }

    def get_iterative(self, level, query):
        entry = self.iterative_cache[level].get(query)
        if entry and datetime.now() < entry['expires']:
            self.stats['iterative_hits'] += 1
            return entry['data']
        elif entry:
            del self.iterative_cache[level][query]
        self.stats['iterative_misses'] += 1
        return None

    def set_iterative(self, level, query, data, ttl=3600):
        self.iterative_cache[level][query] = {
            'data': data,
            'expires': datetime.now() + timedelta(seconds=ttl),
            'cached_at': datetime.now().isoformat()
        }

    def get_stats(self):
        total_hits = self.stats['recursive_hits'] + self.stats['iterative_hits']
        total_requests = self.stats['total_queries']
        hit_rate = (total_hits / total_requests * 100) if total_requests > 0 else 0
        return {
            'recursive_hits': self.stats['recursive_hits'],
            'recursive_misses': self.stats['recursive_misses'],
            'iterative_hits': self.stats['iterative_hits'],
            'iterative_misses': self.stats['iterative_misses'],
            'total_cache_hits': total_hits,
            'total_queries': total_requests,
            'cache_hit_rate_percent': round(hit_rate, 2)
        }


class HybridDNSResolver:
    def __init__(self, log_file="dns_resolution_log.json"):
        self.log_file = log_file
        self.logs = []
        self.cache = DNSCache()
        self.query_stats = []
        self.resolved_from_cache_count = 0
        self.resolved_from_network_count = 0
        self.root_servers = [
            "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
            "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
            "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"
        ]
        self.dns_port = 53
        self.timeout = 5

    def build_dns_query(self, domain, query_id=1, recursion_desired=True):
        flags = 0x0100 if recursion_desired else 0x0000
        header = struct.pack('>HHHHHH', query_id, flags, 1, 0, 0, 0)
        question = b''
        for part in domain.split('.'):
            question += struct.pack('B', len(part))
            question += part.encode('ascii')
        question += b'\x00'
        question += struct.pack('>HH', 1, 1)
        return header + question

    def parse_dns_response(self, response):
        try:
            header = response[:12]
            query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', header)
            ra = (flags & 0x0080) >> 7
            offset = 12
            while offset < len(response):
                length = response[offset]
                if length == 0: offset += 5; break
                if (length & 0xC0) == 0xC0: offset += 2; offset += 4; break
                offset += length + 1
            answers, authorities, additional = [], [], []
            for _ in range(ancount):
                if offset >= len(response): break
                if (response[offset] & 0xC0) == 0xC0: offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1
                if offset + 10 > len(response): break
                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
                offset += 10
                if rtype == 1 and rdlength == 4:
                    ip = '.'.join(str(b) for b in response[offset:offset+4])
                    answers.append({'ip': ip, 'ttl': ttl})
                offset += rdlength
            for _ in range(nscount):
                if offset >= len(response): break
                if (response[offset] & 0xC0) == 0xC0: offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1
                if offset + 10 > len(response): break
                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
                offset += 10
                if rtype == 2:
                    ns_name = self.parse_domain_name(response, offset)
                    if ns_name:
                        authorities.append(ns_name)
                offset += rdlength
            for _ in range(arcount):
                if offset >= len(response): break
                if (response[offset] & 0xC0) == 0xC0: offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1
                if offset + 10 > len(response): break
                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
                offset += 10
                if rtype == 1 and rdlength == 4:
                    ip = '.'.join(str(b) for b in response[offset:offset+4])
                    additional.append({'ip': ip, 'ttl': ttl})
                offset += rdlength
            return {'answers': answers, 'authorities': authorities, 'additional': additional, 'ra': ra}
        except Exception as e:
            return {'answers': [], 'authorities': [], 'additional': [], 'ra': 0, 'error': str(e)}

    def parse_domain_name(self, data, offset):
        try:
            labels, jumped, max_jumps, jumps = [], False, 5, 0
            while True:
                if offset >= len(data): break
                length = data[offset]
                if length == 0: break
                if (length & 0xC0) == 0xC0:
                    if not jumped: jumped = True
                    if jumps >= max_jumps: break
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    offset = pointer
                    jumps += 1
                    continue
                offset += 1
                if offset + length > len(data): break
                label = data[offset:offset+length].decode('ascii', errors='ignore')
                labels.append(label)
                offset += length
            return '.'.join(labels) if labels else None
        except: return None

    def query_dns_server(self, domain, dns_server, recursion_desired=True):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            query = self.build_dns_query(domain, recursion_desired=recursion_desired)
            start_time = time.time()
            sock.sendto(query, (dns_server, self.dns_port))
            response, _ = sock.recvfrom(4096)
            rtt = (time.time() - start_time) * 1000
            sock.close()
            parsed = self.parse_dns_response(response)
            parsed['rtt'] = rtt
            parsed['server'] = dns_server
            return parsed
        except socket.timeout:
            return {'error': 'timeout', 'answers': [], 'authorities': [], 'additional': [], 'ra': 0, 'server': dns_server}
        except Exception as e:
            return {'error': str(e), 'answers': [], 'authorities': [], 'additional': [], 'ra': 0, 'server': dns_server}

    def resolve(self, domain, recursion_desired=True):
        start_time = time.time()
        servers_contacted = []
        resolved_from_cache = False
        
        if recursion_desired:
            cached = self.cache.get_recursive(domain)
            if cached:
                resolved_from_cache = True
                self.resolved_from_cache_count += 1
                latency = (time.time() - start_time) * 1000
                self.query_stats.append({
                    'domain': domain,
                    'servers_contacted': 0,
                    'latency_ms': round(latency, 2),
                    'resolved_from_cache': True,
                    'resolution_method': 'cache'
                })
                return cached

        current_servers, step_num, max_steps = self.root_servers.copy(), 0, 10
        last_ns_level = 'root'
        resolution_method = 'recursive'

        while step_num < max_steps:
            step_num += 1
            for dns_server in current_servers:
                result = self.query_dns_server(domain, dns_server, recursion_desired=True)
                servers_contacted.append(dns_server)

                if 'error' in result:
                    continue

                if result['answers'] and result['ra']:
                    ip = result['answers'][0]['ip']
                    self.cache.set_recursive(domain, ip, result['answers'][0]['ttl'])
                    latency = (time.time() - start_time) * 1000
                    self.resolved_from_network_count += 1
                    self.query_stats.append({
                        'domain': domain,
                        'servers_contacted': len(servers_contacted),
                        'latency_ms': round(latency, 2),
                        'resolved_from_cache': False,
                        'resolution_method': 'recursive'
                    })
                    return ip

                if not result['ra'] or not result['answers']:
                    resolution_method = 'iterative'
                    cached_referral = self.cache.get_iterative(last_ns_level, domain)
                    if cached_referral:
                        current_servers = cached_referral
                        break

                    result_iter = self.query_dns_server(domain, dns_server, recursion_desired=False)
                    servers_contacted.append(dns_server)
                    
                    if 'error' in result_iter:
                        continue

                    if result_iter['answers']:
                        ip = result_iter['answers'][0]['ip']
                        self.cache.set_recursive(domain, ip, result_iter['answers'][0]['ttl'])
                        latency = (time.time() - start_time) * 1000
                        self.resolved_from_network_count += 1
                        self.query_stats.append({
                            'domain': domain,
                            'servers_contacted': len(servers_contacted),
                            'latency_ms': round(latency, 2),
                            'resolved_from_cache': False,
                            'resolution_method': 'iterative_fallback'
                        })
                        return ip

                    referral_ips = [r['ip'] for r in result_iter['additional']] if result_iter['additional'] else []
                    if referral_ips:
                        self.cache.set_iterative(last_ns_level, domain, referral_ips)
                        current_servers = referral_ips
                        last_ns_level = 'tld' if last_ns_level == 'root' else 'auth'
                        break
            else:
                break
        
        latency = (time.time() - start_time) * 1000
        self.query_stats.append({
            'domain': domain,
            'servers_contacted': len(servers_contacted),
            'latency_ms': round(latency, 2),
            'resolved_from_cache': False,
            'resolution_method': 'failed'
        })
        return None

    def get_resolution_stats(self):
        total_resolved = self.resolved_from_cache_count + self.resolved_from_network_count
        percent_from_cache = (self.resolved_from_cache_count / total_resolved * 100) if total_resolved > 0 else 0
        return {
            'resolved_from_cache': self.resolved_from_cache_count,
            'resolved_from_network': self.resolved_from_network_count,
            'total_resolved': total_resolved,
            'percent_resolved_from_cache': round(percent_from_cache, 2)
        }


def analyze_all_urls(url_file, host_name):
    """Analyze ALL URLs with VERBOSE real-time output"""
    print(f"\n{'='*80}")
    print(f"Processing {host_name.upper()}: {url_file}")
    print(f"Recursive Mode: ENABLED (fallback to iterative if RA=0)")
    print(f"{'='*80}\n")
    
    with open(url_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"Total URLs to process: {len(urls)}\n")
    
    resolver = HybridDNSResolver()
    results = []
    successful = 0
    failed = 0
    total_latency = 0
    
    # Real-time processing with URL-by-URL output
    for i, domain in enumerate(urls, 1):
        # Display current query
        print(f"[{i}/{len(urls)}] Resolving: {domain[:50]:<50}", end=" ")
        
        start_time = time.time()
        ip = resolver.resolve(domain, recursion_desired=True)
        latency = (time.time() - start_time) * 1000
        
        # Show result
        if ip:
            successful += 1
            total_latency += latency
            # Check if from cache
            was_cached = resolver.query_stats[-1]['resolved_from_cache'] if resolver.query_stats else False
            cache_indicator = "[CACHE]" if was_cached else "[NET]  "
            print(f"✓ {cache_indicator} {ip:<15} ({latency:>7.0f}ms)")
        else:
            failed += 1
            print(f"✗ Failed          ({latency:>7.0f}ms)")
        
        results.append({
            'domain': domain,
            'ip': ip,
            'latency_ms': round(latency, 2),
            'status': 'success' if ip else 'failed'
        })
    
    # Get statistics
    cache_stats = resolver.cache.get_stats()
    resolution_stats = resolver.get_resolution_stats()
    
    # Calculate metrics
    avg_latency = total_latency / successful if successful > 0 else 0
    success_rate = (successful / len(urls)) * 100 if urls else 0
    total_time_seconds = sum(r['latency_ms'] for r in results) / 1000
    throughput = len(urls) / total_time_seconds if total_time_seconds > 0 else 0
    
    stats = {
        'host': host_name,
        'source_file': url_file,
        'recursive_mode': True,
        'total_queries': len(urls),
        'successful': successful,
        'failed': failed,
        'success_rate_percent': round(success_rate, 2),
        'average_latency_ms': round(avg_latency, 2),
        'throughput_queries_per_sec': round(throughput, 2),
        'cache_statistics': cache_stats,
        'resolution_statistics': resolution_stats,
        'results': results,
        'query_stats': resolver.query_stats
    }
    
    print(f"\n{'='*80}")
    print(f"--- {host_name.upper()} PART E SUMMARY ---")
    print(f"{'='*80}")
    print(f"Total Queries: {len(urls)}")
    print(f"Successful: {successful} ({success_rate:.2f}%)")
    print(f"Failed: {failed}")
    print(f"Average Latency: {avg_latency:.2f} ms")
    print(f"Throughput: {throughput:.2f} queries/sec")
    print(f"\nCache Performance:")
    print(f"  Total Cache Hits: {cache_stats['total_cache_hits']}")
    print(f"  Cache Hit Rate: {cache_stats['cache_hit_rate_percent']}%")
    print(f"\nResolution Source (Part E Key Metric):")
    print(f"  Resolved from Cache: {resolution_stats['resolved_from_cache']} ({resolution_stats['percent_resolved_from_cache']:.2f}%)")
    print(f"  Resolved from Network: {resolution_stats['resolved_from_network']}")
    print(f"{'='*80}\n")
    
    return stats


def generate_graphs(stats, output_dir='graphs'):
    """Generate required graphs for Part E"""
    os.makedirs(output_dir, exist_ok=True)
    
    first_10 = stats['query_stats'][:10]
    domains = [f"Q{i+1}" for i in range(len(first_10))]
    servers = [q['servers_contacted'] for q in first_10]
    latencies = [q['latency_ms'] for q in first_10]
    
    plt.figure(figsize=(12, 6))
    plt.bar(range(len(domains)), servers, color='steelblue')
    plt.xlabel('Query Number', fontsize=12)
    plt.ylabel('Number of DNS Servers Contacted', fontsize=12)
    plt.title(f'DNS Servers Contacted per Query - {stats["host"].upper()}', fontsize=14, fontweight='bold')
    plt.xticks(range(len(domains)), domains)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{output_dir}/{stats["host"]}_servers_contacted.png', dpi=300)
    plt.close()
    
    plt.figure(figsize=(12, 6))
    colors = ['green' if q['resolved_from_cache'] else 'coral' for q in first_10]
    plt.bar(range(len(domains)), latencies, color=colors)
    plt.xlabel('Query Number', fontsize=12)
    plt.ylabel('Latency (ms)', fontsize=12)
    plt.title(f'DNS Resolution Latency - {stats["host"].upper()} (Green=Cache, Orange=Network)', fontsize=14, fontweight='bold')
    plt.xticks(range(len(domains)), domains)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'{output_dir}/{stats["host"]}_latency.png', dpi=300)
    plt.close()
    
    res_stats = stats['resolution_statistics']
    plt.figure(figsize=(8, 6))
    labels = ['Resolved from Cache', 'Resolved from Network']
    sizes = [res_stats['resolved_from_cache'], res_stats['resolved_from_network']]
    colors = ['lightgreen', 'lightskyblue']
    explode = (0.1, 0)
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', 
            startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    plt.title(f'Resolution Source Distribution - {stats["host"].upper()}\n(Part E: % Queries Resolved from Cache)', 
              fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(f'{output_dir}/{stats["host"]}_resolution_source.png', dpi=300)
    plt.close()
    
    print(f"✓ Graphs saved in '{output_dir}/' directory\n")


def generate_report(all_results, output_file):
    """Generate comprehensive Part E report"""
    print(f"\n\n{'='*80}")
    print("PART E: COMPLETE ANALYSIS REPORT")
    print("Recursive DNS Resolution with Cache Performance")
    print(f"{'='*80}\n")
    
    total_queries = sum(r['total_queries'] for r in all_results)
    total_successful = sum(r['successful'] for r in all_results)
    total_failed = sum(r['failed'] for r in all_results)
    avg_latency_overall = sum(r['average_latency_ms'] for r in all_results) / len(all_results)
    avg_throughput = sum(r['throughput_queries_per_sec'] for r in all_results) / len(all_results)
    total_resolved_from_cache = sum(r['resolution_statistics']['resolved_from_cache'] for r in all_results)
    total_resolved_from_network = sum(r['resolution_statistics']['resolved_from_network'] for r in all_results)
    overall_percent_from_cache = (total_resolved_from_cache / (total_resolved_from_cache + total_resolved_from_network) * 100) if (total_resolved_from_cache + total_resolved_from_network) > 0 else 0
    
    print("PART E REQUIRED METRICS (Overall):")
    print(f"  1. Total Queries: {total_queries}")
    print(f"  2. Successfully Resolved: {total_successful}")
    print(f"  3. Failed Resolutions: {total_failed}")
    print(f"  4. Average Lookup Latency: {avg_latency_overall:.2f} ms")
    print(f"  5. Average Throughput: {avg_throughput:.2f} queries/sec")
    print(f"  6. % Queries Resolved from Cache: {overall_percent_from_cache:.2f}%")
    print(f"     - From Cache: {total_resolved_from_cache}")
    print(f"     - From Network: {total_resolved_from_network}")
    print()
    
    print("PER-HOST BREAKDOWN:")
    for result in all_results:
        print(f"\n  {result['host'].upper()}:")
        print(f"    Total Queries: {result['total_queries']}")
        print(f"    Success Rate: {result['success_rate_percent']}%")
        print(f"    Avg Latency: {result['average_latency_ms']} ms")
        print(f"    Throughput: {result['throughput_queries_per_sec']} queries/sec")
        print(f"    % From Cache: {result['resolution_statistics']['percent_resolved_from_cache']}%")
    
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'part': 'E - Recursive DNS Resolution with Cache Analysis',
        'summary': {
            'total_queries': total_queries,
            'total_successful': total_successful,
            'total_failed': total_failed,
            'overall_success_rate_percent': round((total_successful/total_queries*100), 2),
            'average_latency_ms': round(avg_latency_overall, 2),
            'average_throughput_qps': round(avg_throughput, 2),
            'percent_resolved_from_cache': round(overall_percent_from_cache, 2),
            'resolved_from_cache_count': total_resolved_from_cache,
            'resolved_from_network_count': total_resolved_from_network
        },
        'hosts': all_results
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Full Part E report saved to: {output_file}")
    print(f"{'='*80}\n")


def main():
    """Main execution for Part E"""
    cn_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    hosts = {
        'h1': os.path.join(cn_dir, 'urls_h1.txt'),
        'h2': os.path.join(cn_dir, 'urls_h2.txt'),
        'h3': os.path.join(cn_dir, 'urls_h3.txt'),
        'h4': os.path.join(cn_dir, 'urls_h4.txt')
    }
    
    all_results = []
    
    for host_name, url_file in hosts.items():
        if not os.path.exists(url_file):
            print(f"Warning: {url_file} not found, skipping...")
            continue
        
        result = analyze_all_urls(url_file, host_name)
        all_results.append(result)
        
        if host_name == 'h1':
            generate_graphs(result)
    
    output_file = 'part_e_complete_report.json'
    generate_report(all_results, output_file)


if __name__ == '__main__':
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("Installing matplotlib...")
        import subprocess
        subprocess.check_call(['sudo', 'apt', 'install', '-y', 'python3-matplotlib'])
        import matplotlib.pyplot as plt
    
    main()