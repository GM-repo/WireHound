#!/usr/bin/env python3
"""Build and save a network topology graph from a pcap file.

Usage:
    python3 scripts/show_topology.py --input capture.pcap --out-prefix out/topology

Outputs (for out/topology):
    - out/topology.gpickle   (NetworkX serialized graph)
    - out/topology.gexf      (GEXF export)
    - out/topology.png       (figure)
    - out/topology.svg
    - out/topology.pdf

The script derives simple connection tuples from a pcap using `tshark` and
builds a MultiDiGraph where each derived connection creates one directed
edge from `id.orig_h` -> `id.resp_h` with attributes `proto` and `service`.
"""
from __future__ import annotations

import argparse
import csv
import os
import ast
from collections import defaultdict
from typing import Dict, Tuple, List

import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as np
import math
from typing import Optional

# Try to use pygraphviz / pydot for better layouts when available
try:
    from networkx.drawing.nx_agraph import graphviz_layout
    _HAS_GRAPHVIZ = True
except Exception:
    try:
        from networkx.drawing.nx_pydot import graphviz_layout
        _HAS_GRAPHVIZ = True
    except Exception:
        graphviz_layout = None
        _HAS_GRAPHVIZ = False
import networkx as nx
import pickle
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*alltrue.*")
import subprocess
from typing import Iterable


def parse_conn_log(path: str):
    """Parse conn.log with first line separator and second line headers.

    Returns: headers (list), rows (list of dict)
    """
    with open(path, 'r', encoding='utf-8') as f:
        first = f.readline()
        if not first:
            raise SystemExit('Empty file')
        # Example: #separator \x09
        if first.startswith('#separator'):
            sep_token = first.strip().split(None, 1)[1]
            # Interpret escape sequences like \x09
            try:
                sep = ast.literal_eval("'{}'".format(sep_token))
            except Exception:
                # Fallback: raw token
                sep = sep_token
            header_line = f.readline()
        else:
            # no explicit separator line: assume tab-separated and first line is header
            sep = '\t'
            header_line = first

        if not header_line:
            raise SystemExit('Missing header line')
        headers = header_line.strip().split(sep)

        reader = csv.reader(f, delimiter=sep)
        rows = []
        for r in reader:
            if not r or (r and r[0].startswith('#')):
                continue
            # pad/truncate to headers length
            if len(r) < len(headers):
                r += [''] * (len(headers) - len(r))
            rows.append(dict(zip(headers, r)))

    return headers, rows


def parse_pcap(path: str):
    """Derive simple connection rows from a pcap using tshark.

    Returns: headers (list), rows (list of dict)
    Each row contains keys: 'id.orig_h', 'id.resp_h', 'proto', 'service'
    """
    # Use both IPv4 and IPv6 source/dest fields, and tcp/udp dst ports
    cmd = [
        'tshark', '-r', path, '-T', 'fields',
        '-E', 'separator=|',
        '-e', 'ip.src', '-e', 'ipv6.src',
        '-e', 'ip.dst', '-e', 'ipv6.dst',
        '-e', 'tcp.dstport', '-e', 'udp.dstport',
        '-e', '_ws.col.Protocol',
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        raise SystemExit("tshark not found: please install tshark and ensure it's on PATH")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"tshark error: {e.stderr.strip() or e}")

    rows = []
    for line in proc.stdout.splitlines():
        if not line:
            continue
        parts = line.split('|')
        # expected parts: ip.src, ipv6.src, ip.dst, ipv6.dst, tcp.dstport, udp.dstport, protocol
        # pad to length 7
        if len(parts) < 7:
            parts += [''] * (7 - len(parts))

        src = parts[0] or parts[1]
        dst = parts[2] or parts[3]
        tcp_dst = parts[4]
        udp_dst = parts[5]
        proto_col = parts[6] or ''

        if not src or not dst:
            continue

        if tcp_dst:
            proto = 'tcp'
            # service = tcp_dst
        elif udp_dst:
            proto = 'udp'
            # service = udp_dst
        else:
            proto = proto_col.lower() if proto_col else ''
        service = proto_col.lower() if proto_col else ''

        rows.append({
            'id.orig_h': src,
            'id.resp_h': dst,
            'proto': proto,
            'service': service,
        })

    headers = ['id.orig_h', 'id.resp_h', 'proto', 'service']
    return headers, rows


def add_row_to_graph(
    G: nx.MultiDiGraph,
    row: Dict[str, str],
    seen: Dict[Tuple[str, str, str, str], int],
    next_key: int,
) -> int:
    """Add one connection row to ``G`` and return the next available edge key."""
    src = row.get('id.orig_h')
    dst = row.get('id.resp_h')
    proto = row.get('proto', '')
    service = row.get('service', '')
    if not src or not dst:
        return next_key

    G.add_node(src)
    G.add_node(dst)
    edge_id = (src, dst, proto, service)
    if edge_id in seen:
        # Increment the existing edge for this protocol/service tuple.
        key = seen[edge_id]
        G[src][dst][key]['weight'] = G[src][dst][key].get('weight', 1) + 1
    else:
        # Add one edge for this protocol/service tuple and record its key.
        seen[edge_id] = next_key
        G.add_edge(src, dst, key=next_key, proto=proto, service=service, weight=1)
        next_key += 1
    return next_key


def build_graph(rows: List[Dict[str, str]]):
    G = nx.MultiDiGraph()
    # map (src,dst,proto,service) -> edge_key in MultiDiGraph
    seen: Dict[Tuple[str, str, str, str], int] = {}
    next_key = 0
    for row in rows:
        next_key = add_row_to_graph(G, row, seen, next_key)
    return G


def aggregate_edges(G: nx.MultiDiGraph):
    """Return dict mapping (u,v) -> list of dict attrs for each parallel edge."""
    agg = defaultdict(list)
    for u, v, key, data in G.edges(keys=True, data=True):
        agg[(u, v)].append(data)
    return agg


def draw_multidigraph(G: nx.MultiDiGraph, out_path_prefix: str):
    os.makedirs(os.path.dirname(out_path_prefix), exist_ok=True)

    plt.figure(figsize=(12, 9))
    fig = plt.gcf()
    fig.patch.set_facecolor('white')
    fig.patch.set_alpha(1.0)

    def compute_layout(G, seed=42):
        n = max(1, G.number_of_nodes())
        if _HAS_GRAPHVIZ:
            try:
                # use neato for undirected-like spring layout; 'sfdp' for large graphs
                return graphviz_layout(G, prog='neato')
            except Exception:
                pass
        # fallback: tuned spring layout to reduce central clustering
        # choose k proportional to 1/sqrt(n) to spread nodes
        k = 1.2 / math.sqrt(n)
        pos = nx.spring_layout(G, seed=seed, k=k, iterations=200)
        return pos

    pos = compute_layout(G)

    # Validate positions: matplotlib fails if any coord is NaN/Inf. If invalid
    # positions are found, fall back to a spring layout and ensure all coords
    # are finite. Any remaining non-finite coords are set to 0.
    def _positions_finite(p: dict) -> bool:
        for v in p.values():
            try:
                x, y = float(v[0]), float(v[1])
            except Exception:
                return False
            if not (np.isfinite(x) and np.isfinite(y)):
                return False
        return True

    if not _positions_finite(pos):
        try:
            pos = nx.spring_layout(G, seed=42)
        except Exception:
            # last resort: set all positions to origin
            pos = {n: (0.0, 0.0) for n in G.nodes()}

    # Ensure every node has a finite numeric position
    for n in list(G.nodes()):
        v = pos.get(n)
        if v is None:
            pos[n] = (0.0, 0.0)
            continue
        try:
            x, y = float(v[0]), float(v[1])
        except Exception:
            pos[n] = (0.0, 0.0)
            continue
        if not (np.isfinite(x) and np.isfinite(y)):
            pos[n] = (0.0, 0.0)

    # draw nodes
    nx.draw_networkx_nodes(G, pos, node_size=700, node_color='#66c2a5')
    nx.draw_networkx_labels(G, pos, font_size=8)
    ax = plt.gca()
    ax.set_facecolor('white')
    ax.patch.set_alpha(1.0)

    # Prepare parallel edges drawing: for each (u,v), draw each edge with slight curvature
    edge_counts = defaultdict(int)
    for u, v in G.edges():
        edge_counts[(u, v)] += 1

    # Track index per (u,v) to space parallel edges
    index_tracker = defaultdict(int)

    for u, v, key, data in G.edges(keys=True, data=True):
        idx = index_tracker[(u, v)]
        total = edge_counts[(u, v)]
        # compute curvature
        if total == 1:
            rad = 0.0
        else:
            # Keep curvature bounded regardless of how many parallel edges
            # exist.  The previous linear calculation grew without limit
            # (e.g. 128 edges produced radii near +/-12.7), which can make
            # Matplotlib's Bezier-path calculations overflow.
            max_rad = 0.4
            rad = max_rad * ((2 * idx / (total - 1)) - 1)

        # keep constant edge width for clarity
        width = 1.2

        nx.draw_networkx_edges(
            G,
            pos,
            edgelist=[(u, v)],
            connectionstyle=f'arc3,rad={rad:.4f}',
            arrowsize=12,
            width=width,
            alpha=0.8,
        )

        # label: ('proto','service') and optionally weight (weight shown but not used for width)
        proto = data.get('proto', '')
        service = data.get('service', '')
        wt = data.get('weight', 1)
        if wt and wt > 1:
            label = f"({proto},{service}) [{wt}]"
        else:
            label = f"({proto},{service})"

        # compute label position midway
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        xm, ym = (x1 + x2) / 2, (y1 + y2) / 2
        # offset label perpendicular to edge by rad
        dx, dy = x2 - x1, y2 - y1
        # perpendicular
        px, py = -dy, dx
        # normalize
        norm = (px ** 2 + py ** 2) ** 0.5
        if norm != 0:
            px /= norm
            py /= norm

        label_offset = rad * 0.5 * 2.5
        plt.text(xm + px * label_offset, ym + py * label_offset, label, fontsize=7, horizontalalignment='center', verticalalignment='center', bbox=dict(facecolor='white', alpha=0.6, edgecolor='none'))

        index_tracker[(u, v)] += 1

    plt.axis('off')
    # Save images with an explicit white background to avoid transparent PNGs
    face = fig.get_facecolor()
    for ext in ('png', 'svg', 'pdf'):
        out = f"{out_path_prefix}.{ext}"
        plt.savefig(out, bbox_inches='tight', facecolor=face, transparent=False)
        # If PNG has an alpha channel, composite over white and re-save without alpha
        if ext == 'png':
            try:
                img = mpimg.imread(out)
                if img.ndim == 3 and img.shape[2] == 4:
                    alpha = img[:, :, 3]
                    rgb = img[:, :, :3]
                    # alpha may be 0..1 floats; composite over white
                    if np.issubdtype(alpha.dtype, np.floating):
                        comp = rgb * alpha[:, :, None] + (1.0 - alpha)[:, :, None]
                    else:
                        # uint8 0..255
                        alpha_f = alpha.astype('float32') / 255.0
                        comp = rgb.astype('float32') * alpha_f[:, :, None] + (1.0 - alpha_f)[:, :, None]
                    mpimg.imsave(out, comp)
            except Exception:
                pass
    plt.close()


def save_graph(G: nx.MultiDiGraph, out_path_prefix: str):
    os.makedirs(os.path.dirname(out_path_prefix), exist_ok=True)
    gpickle_path = f"{out_path_prefix}.gpickle"
    # Use pickle.dump for compatibility across NetworkX versions
    with open(gpickle_path, 'wb') as fh:
        pickle.dump(G, fh)
    try:
        gexf_path = f"{out_path_prefix}.gexf"
        nx.write_gexf(G, gexf_path)
    except Exception:
        # write_gexf may fail for complex attributes; ignore if so
        pass


def main():
    p = argparse.ArgumentParser(description='Build topology graph from pcap')
    p.add_argument('--input', '-i', required=True, help='Path to pcap file')
    p.add_argument('--out-prefix', '-o', required=True, help='Output path prefix (dir+basename)')
    args = p.parse_args()

    headers, rows = parse_pcap(args.input)
    # Build per-source graphs and save each in its own folder under out-prefix
    base_out = args.out_prefix
    os.makedirs(base_out, exist_ok=True)

    # Build each per-source graph and the full-network graph in the same pass.
    # This avoids a second full build over ``rows`` for the consolidated view.
    seen_src = []
    source_graphs: Dict[str, nx.MultiDiGraph] = {}
    source_seen: Dict[str, Dict[Tuple[str, str, str, str], int]] = {}
    source_next_keys: Dict[str, int] = {}
    consolidated_graph = nx.MultiDiGraph()
    consolidated_seen: Dict[Tuple[str, str, str, str], int] = {}
    consolidated_next_key = 0

    for r in rows:
        src = r.get('id.orig_h')
        if not src:
            continue
        if src not in source_graphs:
            seen_src.append(src)
            source_graphs[src] = nx.MultiDiGraph()
            source_seen[src] = {}
            source_next_keys[src] = 0

        source_next_keys[src] = add_row_to_graph(
            source_graphs[src], r, source_seen[src], source_next_keys[src]
        )
        consolidated_next_key = add_row_to_graph(
            consolidated_graph, r, consolidated_seen, consolidated_next_key
        )

    def sanitize(name: str) -> str:
        # make filesystem-safe folder name
        return name.replace('/', '_').replace('\\', '_').replace(':', '_')

    for src in seen_src:
        print(f'Processing source: {src}')
        G = source_graphs[src]
        folder = os.path.join(base_out, sanitize(src))
        os.makedirs(folder, exist_ok=True)
        out_prefix = os.path.join(folder, 'topology')
        save_graph(G, out_prefix)
        draw_multidigraph(G, out_prefix)

    # Save the full-network view in one sibling folder, not a nested output
    # hierarchy.  It has already been assembled alongside the per-source graphs.
    if consolidated_graph.number_of_nodes():
        print('Processing consolidated topology')
        consolidated_folder = os.path.join(base_out, 'consolidated_topology')
        out_prefix = os.path.join(consolidated_folder, 'topology')
        save_graph(consolidated_graph, out_prefix)
        draw_multidigraph(consolidated_graph, out_prefix)


if __name__ == '__main__':
    main()
