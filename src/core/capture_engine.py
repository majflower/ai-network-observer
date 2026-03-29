#!/usr/bin/env python3
"""
Capture Engine - Abstraction layer for packet capture
Supports Scapy (prototyping) and eBPF (production)
"""

from abc import ABC, abstractmethod
from typing import Callable, Optional
import logging

logger = logging.getLogger(__name__)


class CaptureBackend(ABC):
    """Abstract base class for capture backends"""
    
    @abstractmethod
    def start_capture(self, interface: str, callback: Callable, filter_expr: str = ""):
        """Start packet capture"""
        pass
    
    @abstractmethod
    def stop_capture(self):
        """Stop packet capture"""
        pass


class ScapyCaptureBackend(CaptureBackend):
    """Scapy-based capture (for prototyping)"""
    
    def __init__(self):
        from scapy.all import sniff
        self.sniff = sniff
        self.is_running = False
        
    def start_capture(self, interface: str, callback: Callable, filter_expr: str = ""):
        """Start Scapy capture"""
        logger.info(f"Starting Scapy capture on {interface}")
        self.is_running = True
        
        try:
            self.sniff(
                iface=interface,
                prn=callback,
                filter=filter_expr,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            logger.error(f"Scapy capture error: {e}")
            self.is_running = False
    
    def stop_capture(self):
        """Stop capture"""
        self.is_running = False
        logger.info("Scapy capture stopped")


class EBPFCaptureBackend(CaptureBackend):
    """eBPF-based capture (for production performance)"""
    
    def __init__(self):
        try:
            from bcc import BPF
            self.BPF = BPF
            self.bpf_program = None
        except ImportError:
            raise ImportError("BCC not installed. Install with: pip install bcc")
    
    def start_capture(self, interface: str, callback: Callable, filter_expr: str = ""):
        """Start eBPF capture with custom BPF program"""
        logger.info(f"Starting eBPF capture on {interface}")
        
        # eBPF program for efficient packet filtering
        bpf_text = """
        #include <uapi/linux/ptrace.h>
        #include <net/sock.h>
        #include <bcc/proto.h>
        
        struct packet_t {
            u64 timestamp;
            u32 src_ip;
            u32 dst_ip;
            u16 src_port;
            u16 dst_port;
            u8 protocol;
            u32 payload_len;
        };
        
        BPF_PERF_OUTPUT(packets);
        
        int packet_filter(struct __sk_buff *skb) {
            struct packet_t pkt = {};
            
            // Extract packet metadata
            pkt.timestamp = bpf_ktime_get_ns();
            
            // Parse Ethernet/IP headers
            // ... (simplified for space)
            
            packets.perf_submit(skb, &pkt, sizeof(pkt));
            return 0;
        }
        """
        
        self.bpf_program = self.BPF(text=bpf_text)
        function_name = self.bpf_program.load_func("packet_filter", self.BPF.SOCKET_FILTER)
        self.bpf_program.attach_raw_socket(function_name, interface)
        
        # Poll events
        self.bpf_program["packets"].open_perf_buffer(callback)
        
        while True:
            try:
                self.bpf_program.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    
    def stop_capture(self):
        """Stop eBPF capture"""
        if self.bpf_program:
            self.bpf_program.cleanup()
        logger.info("eBPF capture stopped")


class CaptureEngine:
    """Main capture engine with backend selection"""
    
    def __init__(self, backend: str = "scapy", performance_mode: bool = False):
        """
        Initialize capture engine
        
        Args:
            backend: "scapy" or "ebpf"
            performance_mode: Use eBPF if True and available
        """
        self.backend_name = backend
        
        if performance_mode or backend == "ebpf":
            try:
                self.backend = EBPFCaptureBackend()
                logger.info("Using eBPF backend (high performance)")
            except ImportError:
                logger.warning("eBPF not available, falling back to Scapy")
                self.backend = ScapyCaptureBackend()
        else:
            self.backend = ScapyCaptureBackend()
            logger.info("Using Scapy backend (prototyping mode)")
    
    def start(self, interface: str, packet_handler: Callable, bpf_filter: str = ""):
        """
        Start packet capture
        
        Args:
            interface: Network interface (e.g., "eth0")
            packet_handler: Callback function for each packet
            bpf_filter: BPF filter expression
        """
        logger.info(f"Starting capture on {interface} with filter: {bpf_filter or 'none'}")
        self.backend.start_capture(interface, packet_handler, bpf_filter)
    
    def stop(self):
        """Stop capture"""
        self.backend.stop_capture()


if __name__ == "__main__":
    # Test the capture engine
    logging.basicConfig(level=logging.INFO)
    
    def test_handler(packet):
        print(f"Packet received: {packet.summary() if hasattr(packet, 'summary') else packet}")
    
    engine = CaptureEngine(backend="scapy")
    try:
        engine.start("eth0", test_handler, "tcp port 80 or tcp port 443")
    except KeyboardInterrupt:
        engine.stop()
