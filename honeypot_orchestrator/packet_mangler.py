import threading
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# NetfilterQueue and scapy might not be installed in all environments
# (e.g. during simple tests) so we import them conditionally or catch errors
try:
    from netfilterqueue import NetfilterQueue
    from scapy.all import IP, TCP
    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False
    logger.warning("NetfilterQueue or scapy not found. Packet mangling will be disabled.")


class PacketMangler:
    """
    Background service that intercepts outgoing packets via NFQUEUE
    and modifies their TCP/IP headers to defeat OS fingerprinting.
    """
    def __init__(self, queue_num: int = 1):
        self.queue_num = queue_num
        self.active_profile = "linux_server"
        self._nfqueue: Optional['NetfilterQueue'] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._ip_id_counter = 10000

    def set_profile(self, profile_name: str):
        logger.info(f"PacketMangler profile updated to: {profile_name}")
        self.active_profile = profile_name

    def _modify_packet(self, pkt):
        if not HAS_NFQUEUE:
            pkt.accept()
            return

        try:
            # We only mangle when Windows profile is active
            if self.active_profile != "windows_server":
                pkt.accept()
                return

            scapy_pkt = IP(pkt.get_payload())

            # Only target TCP packets
            if scapy_pkt.haslayer(TCP):
                tcp_layer = scapy_pkt[TCP]
                
                # We specifically want to mangle SYN-ACK responses (flags: S and A)
                # In Scapy flags are represented as strings like "SA", "S", "A"
                if tcp_layer.flags == "SA":
                    
                    # 1. Modify IP ID to be incremental (typical for Windows)
                    scapy_pkt.id = self._ip_id_counter
                    self._ip_id_counter = (self._ip_id_counter + 1) % 65535
                    
                    # 2. Modify TCP Window Size
                    # Windows Server typically uses 8192 or 64240 for initial window
                    tcp_layer.window = 8192

                    # 3. Rewrite TCP Options to Windows Order
                    # Linux default: [MSS, SACKOK, TS, NOP, WScale]
                    # Windows default: [MSS, NOP, WScale, NOP, NOP, SACKOK]
                    # Since we disabled everything but MSS via sysctl, we now 
                    # rebuild the options from scratch to perfectly mimic Windows.
                    new_options = [
                        ('MSS', 1460),
                        ('NOP', None),
                        ('WScale', 8),
                        ('NOP', None),
                        ('NOP', None),
                        ('SAckOK', b'')
                    ]
                    tcp_layer.options = new_options

                    # Delete checksums so Scapy recalculates them
                    del scapy_pkt.chksum
                    del tcp_layer.chksum

                    # Set the modified payload back
                    pkt.set_payload(bytes(scapy_pkt))
            
            pkt.accept()
            
        except Exception as e:
            logger.error(f"Error in packet mangling: {e}")
            # Failsafe: if we crash, just accept the original packet
            pkt.accept()

    def start(self):
        if not HAS_NFQUEUE:
            logger.warning("PacketMangler cannot start because NetfilterQueue is not installed.")
            return

        if self._running:
            return

        self._running = True
        self._nfqueue = NetfilterQueue()
        self._nfqueue.bind(self.queue_num, self._modify_packet)
        
        self._thread = threading.Thread(target=self._run_queue, daemon=True, name="PacketManglerThread")
        self._thread.start()
        logger.info(f"PacketMangler started on queue {self.queue_num}")

    def _run_queue(self):
        try:
            self._nfqueue.run()
        except Exception as e:
            if self._running:
                logger.error(f"PacketMangler queue stopped with error: {e}")

    def stop(self):
        self._running = False
        if self._nfqueue:
            try:
                self._nfqueue.unbind()
            except Exception:
                pass
        
        logger.info("PacketMangler stopped.")
