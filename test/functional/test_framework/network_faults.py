# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Network fault injection for chaos testing

Provides tools for simulating network failures:
- Network partitions (block traffic between nodes)
- Latency injection (add delay to packets)
- Packet loss (drop random packets)
- Bandwidth limiting

Platform support:
- Linux: Uses iptables and tc (traffic control)
- Windows: Uses netsh and clumsy (if available)
"""

import os
import sys
import subprocess
import logging
from typing import List, Optional, Tuple

log = logging.getLogger("NetworkFaults")


class NetworkFaultInjector:
    """Injects network faults for chaos testing

    Supports network partitions, latency, and packet loss.
    Tracks all applied faults for cleanup.
    """

    def __init__(self):
        """Initialize fault injector"""
        self.platform = sys.platform
        self.is_linux = self.platform.startswith('linux')
        self.is_windows = self.platform == 'win32'

        # Track applied faults for cleanup
        self._partitions: List[Tuple[str, int, str, int]] = []  # (ip_a, port_a, ip_b, port_b)
        self._latency_rules: List[Tuple[str, int, int]] = []  # (ip, port, latency_ms)
        self._packet_loss_rules: List[Tuple[str, int, int]] = []  # (ip, port, loss_percent)

    def partition_nodes(self, node_a, node_b) -> bool:
        """Block all traffic between two nodes

        Args:
            node_a: First TestNode instance
            node_b: Second TestNode instance

        Returns:
            True if partition was successfully applied
        """
        ip_a = node_a.host
        port_a = node_a.p2p_port
        ip_b = node_b.host
        port_b = node_b.p2p_port

        log.info(f"Creating network partition: {ip_a}:{port_a} <-> {ip_b}:{port_b}")

        if self.is_linux:
            # Block traffic in both directions using iptables
            try:
                # Block A -> B
                subprocess.run([
                    'iptables', '-A', 'INPUT',
                    '-s', ip_a, '-p', 'tcp', '--dport', str(port_b),
                    '-j', 'DROP'
                ], check=True, capture_output=True)

                # Block B -> A
                subprocess.run([
                    'iptables', '-A', 'INPUT',
                    '-s', ip_b, '-p', 'tcp', '--dport', str(port_a),
                    '-j', 'DROP'
                ], check=True, capture_output=True)

                self._partitions.append((ip_a, port_a, ip_b, port_b))
                return True

            except subprocess.CalledProcessError as e:
                log.error(f"Failed to create partition (need root?): {e}")
                return False
            except FileNotFoundError:
                log.error("iptables not found - network faults require root on Linux")
                return False

        elif self.is_windows:
            # Use Windows Firewall (netsh)
            try:
                rule_name_ab = f"dilithion_test_block_{ip_a}_{port_a}_to_{ip_b}_{port_b}"
                rule_name_ba = f"dilithion_test_block_{ip_b}_{port_b}_to_{ip_a}_{port_a}"

                # Block A -> B
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name_ab}',
                    'dir=in', 'action=block', 'protocol=tcp',
                    f'localport={port_b}', f'remoteip={ip_a}'
                ], check=True, capture_output=True)

                # Block B -> A
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name_ba}',
                    'dir=in', 'action=block', 'protocol=tcp',
                    f'localport={port_a}', f'remoteip={ip_b}'
                ], check=True, capture_output=True)

                self._partitions.append((ip_a, port_a, ip_b, port_b))
                return True

            except subprocess.CalledProcessError as e:
                log.error(f"Failed to create partition (need admin?): {e}")
                return False

        else:
            log.warning(f"Network partitions not supported on {self.platform}")
            return False

    def heal_partition(self, node_a, node_b) -> bool:
        """Remove network partition between two nodes

        Args:
            node_a: First TestNode instance
            node_b: Second TestNode instance

        Returns:
            True if partition was successfully removed
        """
        ip_a = node_a.host
        port_a = node_a.p2p_port
        ip_b = node_b.host
        port_b = node_b.p2p_port

        log.info(f"Healing network partition: {ip_a}:{port_a} <-> {ip_b}:{port_b}")

        if self.is_linux:
            try:
                # Remove both directions
                subprocess.run([
                    'iptables', '-D', 'INPUT',
                    '-s', ip_a, '-p', 'tcp', '--dport', str(port_b),
                    '-j', 'DROP'
                ], capture_output=True)

                subprocess.run([
                    'iptables', '-D', 'INPUT',
                    '-s', ip_b, '-p', 'tcp', '--dport', str(port_a),
                    '-j', 'DROP'
                ], capture_output=True)

                self._partitions = [p for p in self._partitions
                                   if p != (ip_a, port_a, ip_b, port_b)]
                return True

            except Exception as e:
                log.error(f"Failed to heal partition: {e}")
                return False

        elif self.is_windows:
            try:
                rule_name_ab = f"dilithion_test_block_{ip_a}_{port_a}_to_{ip_b}_{port_b}"
                rule_name_ba = f"dilithion_test_block_{ip_b}_{port_b}_to_{ip_a}_{port_a}"

                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name_ab}'
                ], capture_output=True)

                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name_ba}'
                ], capture_output=True)

                self._partitions = [p for p in self._partitions
                                   if p != (ip_a, port_a, ip_b, port_b)]
                return True

            except Exception as e:
                log.error(f"Failed to heal partition: {e}")
                return False

        return False

    def add_latency(self, node, latency_ms: int) -> bool:
        """Add network latency to a node's traffic

        Args:
            node: TestNode instance
            latency_ms: Latency to add in milliseconds

        Returns:
            True if latency was successfully applied
        """
        log.info(f"Adding {latency_ms}ms latency to node {node.index}")

        if self.is_linux:
            try:
                # Use tc (traffic control) to add delay
                # This requires the interface name, which we approximate
                subprocess.run([
                    'tc', 'qdisc', 'add', 'dev', 'lo', 'root',
                    'netem', 'delay', f'{latency_ms}ms'
                ], check=True, capture_output=True)

                self._latency_rules.append((node.host, node.p2p_port, latency_ms))
                return True

            except subprocess.CalledProcessError as e:
                log.error(f"Failed to add latency (need root?): {e}")
                return False
            except FileNotFoundError:
                log.error("tc not found - latency injection requires iproute2")
                return False

        else:
            log.warning(f"Latency injection not supported on {self.platform}")
            log.warning("Consider using 'clumsy' tool on Windows for latency simulation")
            return False

    def add_packet_loss(self, node, loss_percent: int) -> bool:
        """Add packet loss to a node's traffic

        Args:
            node: TestNode instance
            loss_percent: Percentage of packets to drop (0-100)

        Returns:
            True if packet loss was successfully applied
        """
        log.info(f"Adding {loss_percent}% packet loss to node {node.index}")

        if self.is_linux:
            try:
                subprocess.run([
                    'tc', 'qdisc', 'add', 'dev', 'lo', 'root',
                    'netem', 'loss', f'{loss_percent}%'
                ], check=True, capture_output=True)

                self._packet_loss_rules.append((node.host, node.p2p_port, loss_percent))
                return True

            except subprocess.CalledProcessError as e:
                log.error(f"Failed to add packet loss: {e}")
                return False

        else:
            log.warning(f"Packet loss injection not supported on {self.platform}")
            return False

    def heal_all(self):
        """Remove all injected faults

        Should be called in test cleanup to ensure no faults persist.
        """
        log.info("Healing all network faults...")

        errors = []

        # Remove partitions
        for ip_a, port_a, ip_b, port_b in self._partitions[:]:
            try:
                if self.is_linux:
                    subprocess.run([
                        'iptables', '-D', 'INPUT',
                        '-s', ip_a, '-p', 'tcp', '--dport', str(port_b),
                        '-j', 'DROP'
                    ], capture_output=True)
                    subprocess.run([
                        'iptables', '-D', 'INPUT',
                        '-s', ip_b, '-p', 'tcp', '--dport', str(port_a),
                        '-j', 'DROP'
                    ], capture_output=True)
                elif self.is_windows:
                    rule_name_ab = f"dilithion_test_block_{ip_a}_{port_a}_to_{ip_b}_{port_b}"
                    rule_name_ba = f"dilithion_test_block_{ip_b}_{port_b}_to_{ip_a}_{port_a}"
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name={rule_name_ab}'
                    ], capture_output=True)
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name={rule_name_ba}'
                    ], capture_output=True)
            except Exception as e:
                errors.append(f"Failed to remove partition {ip_a}:{port_a} <-> {ip_b}:{port_b}: {e}")

        self._partitions.clear()

        # Remove tc rules (Linux only)
        if self.is_linux and (self._latency_rules or self._packet_loss_rules):
            try:
                subprocess.run([
                    'tc', 'qdisc', 'del', 'dev', 'lo', 'root'
                ], capture_output=True)
            except Exception as e:
                errors.append(f"Failed to remove tc rules: {e}")

        self._latency_rules.clear()
        self._packet_loss_rules.clear()

        if errors:
            for error in errors:
                log.error(error)
            return False

        log.info("All network faults healed")
        return True

    def get_active_faults(self) -> dict:
        """Get summary of currently active faults

        Returns:
            Dict with counts and details of active faults
        """
        return {
            'partitions': len(self._partitions),
            'latency_rules': len(self._latency_rules),
            'packet_loss_rules': len(self._packet_loss_rules),
            'partition_details': list(self._partitions),
            'latency_details': list(self._latency_rules),
            'packet_loss_details': list(self._packet_loss_rules),
        }
