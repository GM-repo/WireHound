#!/usr/bin/env python3
# Sample command: sudo python3 scripts/pre_processing/describe_network.py --input out/topology/consolidated_topology/topology.gexf --output out/findings/network_description.txt --api-key <key>
"""Describe a consolidated topology GEXF file with the Gemini API.

The script first creates a bounded, structured summary of the topology so the
model receives the relevant hosts, subnets, communications, and potential
anomaly signals without sending an unbounded edge list.

Example:
    sudo python3 scripts/pre_processing/describe_network.py --input out/topology/consolidated_topology/topology.gexf --output out/findings/network_description.txt
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import networkx as nx


DEFAULT_INPUT = "out/topology/consolidated_topology/topology.gexf"
DEFAULT_OUTPUT = "out/findings/network_description.txt"
DEFAULT_MODEL = "gemini-3.6-flash"
MAX_CONNECTIONS_IN_PROMPT = 100
MAX_PROTOCOL_SERVICES_IN_PROMPT = 100


def _as_int(value: Any, default: int = 1) -> int:
    """Convert a GEXF edge weight to an integer without failing on bad data."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def subnet_for(host: str) -> str:
    """Return a useful aggregation subnet, or ``non-IP`` for other labels."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "non-IP"
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def edge_records(graph: nx.Graph) -> list[tuple[str, str, str, str, int]]:
    """Aggregate repeated source/destination/protocol/service connections."""
    records: Counter[tuple[str, str, str, str]] = Counter()
    edges = graph.edges(data=True, keys=True) if graph.is_multigraph() else graph.edges(data=True)
    for edge in edges:
        source, destination, *rest = edge
        attributes = rest[-1]
        protocol = str(attributes.get("proto", "unknown") or "unknown").lower()
        service = str(attributes.get("service", "unknown") or "unknown")
        records[(str(source), str(destination), protocol, service)] += _as_int(
            attributes.get("weight", 1)
        )
    return [(*connection, count) for connection, count in records.items()]


def build_topology_summary(graph: nx.Graph) -> dict[str, Any]:
    """Create compact, evidence-based context for the model prompt."""
    records = edge_records(graph)
    subnets: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes:
        subnets[subnet_for(str(node))].add(str(node))

    protocol_services: Counter[tuple[str, str]] = Counter()
    inbound: Counter[str] = Counter()
    outbound: Counter[str] = Counter()
    peer_count: dict[str, set[str]] = defaultdict(set)
    cross_subnet: Counter[tuple[str, str]] = Counter()
    for source, destination, protocol, service, count in records:
        protocol_services[(protocol, service)] += count
        outbound[source] += count
        inbound[destination] += count
        peer_count[source].add(destination)
        if subnet_for(source) != subnet_for(destination):
            cross_subnet[(subnet_for(source), subnet_for(destination))] += count

    # anomaly_signals = []
    # for source, peers in sorted(peer_count.items(), key=lambda item: len(item[1]), reverse=True)[:10]:
    #     if len(peers) >= 20:
    #         anomaly_signals.append(
    #             f"High fan-out: {source} contacted {len(peers)} distinct peers "
    #             f"({outbound[source]} observed connections)."
    #         )
    # for destination, count in inbound.most_common(10):
    #     if count >= 100:
    #         anomaly_signals.append(
    #             f"High inbound concentration: {destination} received {count} observed connections."
    #         )

    sorted_connections = sorted(records, key=lambda item: item[4], reverse=True)
    sorted_protocol_services = protocol_services.most_common()
    return {
        "node_count": graph.number_of_nodes(),
        "distinct_connection_count": len(records),
        "observed_connection_count": sum(count for *_, count in records),
        "subnets": [
            {"subnet": subnet, "host_count": len(hosts), "hosts": sorted(hosts)}
            for subnet, hosts in sorted(subnets.items())
        ],
        "protocol_service_counts": [
            {"protocol": protocol, "service": service, "connections": count}
            for (protocol, service), count in sorted_protocol_services[:MAX_PROTOCOL_SERVICES_IN_PROMPT]
        ],
        "protocol_service_counts_truncated": len(sorted_protocol_services)
        > MAX_PROTOCOL_SERVICES_IN_PROMPT,
        "cross_subnet_connections": [
            {"source_subnet": source, "destination_subnet": destination, "connections": count}
            for (source, destination), count in cross_subnet.most_common()
        ],
        "top_connections": [
            {
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "service": service,
                "connections": count,
            }
            for source, destination, protocol, service, count in sorted_connections[
                :MAX_CONNECTIONS_IN_PROMPT
            ]
        ],
        # "possible_anomaly_signals": anomaly_signals or ["No high-volume topology signals triggered."],
    }


def request_gemini(summary: dict[str, Any], api_key: str, model: str) -> str:
    """Submit the topology evidence to Gemini and return its textual analysis."""
    prompt = """You are a network-security analyst. Analyze only the supplied
topology evidence. Give a concise report with these headings: Network topology,
Subnet roles, Infrastructure inferred from protocols/services, and Anomalies.
Identify communication paths and likely subnet purposes, clearly label
inferences as likely or uncertain. Also, for each inference, add a two-sentence summary of
how you made the inference. Do not invent hosts, services, ownership, or security findings not supported by the data. If any connection in the infered network topology seems suspicious, describe why it is suspicious and what normalcy conditions it violates, under a heading "Suspicious Connections".
If no suspicious connections are found, state "No suspicious connections found" under the heading
"Suspicious Connections"
.

Topology evidence:
""" + json.dumps(summary, indent=2, sort_keys=True)

    body = json.dumps(
        {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.2}}
    ).encode("utf-8")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gemini API request failed ({error.code}): {detail}") from error
    except URLError as error:
        raise RuntimeError(f"Could not reach the Gemini API: {error.reason}") from error

    try:
        return payload["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError(f"Gemini returned no text response: {json.dumps(payload)}") from error


def main() -> None:
    parser = argparse.ArgumentParser(description="Describe a network topology GEXF with Gemini")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to consolidated topology.gexf")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Description output file")
    parser.add_argument("--api-key", default=os.getenv("GEMINI_API_KEY"), help="Gemini API key; defaults to GEMINI_API_KEY")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Gemini model name")
    args = parser.parse_args()

    if not args.api_key:
        parser.error("provide --api-key or set the GEMINI_API_KEY environment variable")
    input_path = Path(args.input)
    if not input_path.is_file():
        parser.error(f"GEXF input file does not exist: {input_path}")

    summary = build_topology_summary(nx.read_gexf(input_path))
    print(summary)
    description = request_gemini(summary, args.api_key, args.model)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(description + "\n", encoding="utf-8")
    print(f"Wrote network description to {output_path}")


if __name__ == "__main__":
    main()
