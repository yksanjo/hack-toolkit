#!/usr/bin/env python3
"""
topo-hash: Topology-Based File Integrity Checker
Uses topological data analysis to create unique file fingerprints.
"""

import hashlib
import networkx as nx
import numpy as np
from pathlib import Path
import argparse
from loguru import logger


def compute_topo_hash(filepath: Path) -> str:
    """Compute topological hash of file."""
    # Read file as bytes
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if len(data) < 100:
        # For small files, use regular hash
        return hashlib.sha256(data).hexdigest()
    
    # Convert to graph structure
    # Create nodes from byte values and edges from sequences
    G = nx.Graph()
    
    # Add nodes (unique byte values)
    byte_values = list(set(data))
    G.add_nodes_from(byte_values)
    
    # Add edges (adjacent bytes)
    for i in range(len(data) - 1):
        byte1 = data[i]
        byte2 = data[i + 1]
        if G.has_edge(byte1, byte2):
            G[byte1][byte2]['weight'] += 1
        else:
            G.add_edge(byte1, byte2, weight=1)
    
    # Compute topological features
    features = []
    
    # Number of connected components
    features.append(nx.number_connected_components(G))
    
    # Average clustering
    if G.number_of_nodes() > 0:
        features.append(nx.average_clustering(G))
    else:
        features.append(0.0)
    
    # Density
    features.append(nx.density(G))
    
    # Combine with traditional hash
    traditional_hash = hashlib.sha256(data).hexdigest()
    topo_features = ','.join(map(str, features))
    
    combined = f"{traditional_hash}:{topo_features}"
    return hashlib.sha256(combined.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Topology-based file integrity checker")
    parser.add_argument("--file", type=str, required=True, help="File to hash")
    parser.add_argument("--verify", type=str, help="Hash to verify against")
    parser.add_argument("--save", type=str, help="Save hash to file")
    
    args = parser.parse_args()
    
    filepath = Path(args.file)
    if not filepath.exists():
        logger.error(f"File not found: {filepath}")
        return
    
    hash_value = compute_topo_hash(filepath)
    
    if args.verify:
        if hash_value == args.verify:
            logger.success("✓ File integrity verified")
        else:
            logger.error("✗ File integrity check failed - file has been modified")
    elif args.save:
        with open(args.save, 'w') as f:
            f.write(hash_value)
        logger.info(f"Hash saved to {args.save}")
    else:
        print(f"Topo-hash: {hash_value}")


if __name__ == "__main__":
    main()

