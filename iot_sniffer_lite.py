#!/usr/bin/env python3
"""
iot-sniffer-lite: Passive IoT Monitor with LLM-Based Log Summarizer
"""

import ollama
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import argparse
from loguru import logger


class IoTSniffer:
    """Passive IoT device monitor."""
    
    def __init__(self, interface: str = None, model: str = "phi3:mini"):
        """Initialize IoT sniffer."""
        self.interface = interface
        self.model = model
        self.device_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "connections": set()})
        self.start_time = datetime.now()
    
    def process_packet(self, packet):
        """Process captured packet."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Identify device (simplified - in production, use MAC address mapping)
            device_id = src_ip.split('.')[-1]  # Last octet as device ID
            
            self.device_stats[device_id]["packets"] += 1
            self.device_stats[device_id]["bytes"] += len(packet)
            self.device_stats[device_id]["connections"].add(dst_ip)
    
    def summarize(self) -> str:
        """Generate LLM summary of network activity."""
        summary_lines = []
        summary_lines.append(f"Network activity summary (since {self.start_time}):\n")
        
        for device_id, stats in self.device_stats.items():
            summary_lines.append(
                f"Device {device_id}: {stats['packets']} packets, "
                f"{stats['bytes']} bytes, {len(stats['connections'])} unique connections"
            )
        
        summary_text = "\n".join(summary_lines)
        
        prompt = f"""Analyze this IoT network activity summary and identify any security concerns:

{summary_text}

Provide a brief security assessment focusing on:
- Unusual traffic patterns
- Potential security risks
- Recommendations

Assessment:"""
        
        try:
            response = ollama.generate(model=self.model, prompt=prompt)
            return response["response"]
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return summary_text
    
    def start(self, duration: int = 60):
        """Start sniffing for specified duration."""
        logger.info(f"Starting IoT sniffer on {self.interface or 'all interfaces'}")
        logger.info(f"Capturing for {duration} seconds...")
        
        sniff(
            iface=self.interface,
            prn=self.process_packet,
            timeout=duration
        )
        
        logger.info("Capture complete. Generating summary...")
        summary = self.summarize()
        print("\n" + "="*60)
        print(summary)
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description="Passive IoT monitor with LLM summarization")
    parser.add_argument("--interface", type=str, help="Network interface to monitor")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration (seconds)")
    parser.add_argument("--model", type=str, default="phi3:mini", help="LLM model to use")
    
    args = parser.parse_args()
    
    sniffer = IoTSniffer(interface=args.interface, model=args.model)
    sniffer.start(duration=args.duration)


if __name__ == "__main__":
    main()




