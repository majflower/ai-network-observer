import hashlib
import logging  # <--- AJOUTER CETTE LIGNE ICI
from typing import Optional, Dict
from scapy.all import TCP

# Importation sécurisée de TLS
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
except ImportError:
    # Fallback si cryptography n'est pas installé
    TLS = type('TLS', (), {})
    TLSClientHello = type('TLSClientHello', (), {})
    TLSServerHello = type('TLSServerHello', (), {})

# Maintenant logging est défini, cette ligne fonctionnera :
logger = logging.getLogger(__name__)


class TLSFingerprinter:
    """Extract JA3 (client) and JA3S (server) fingerprints from TLS handshakes"""
    
    def __init__(self):
        self.ja3_database = {}  # Cache for known fingerprints
        self.load_ja3_signatures()
    
    def load_ja3_signatures(self):
        """Load known JA3 signatures for identification"""
        # Example signatures (in production, load from database)
        self.ja3_database = {
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0":
                "Chrome 96+",
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0":
                "Firefox 95+",
            # Add more signatures...
        }
    
    def extract_ja3(self, packet) -> Optional[Dict]:
        """
        Extract JA3 fingerprint from TLS ClientHello
        
        JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        """
        try:
            if not packet.haslayer(TLS):
                return None
            
            tls_layer = packet[TLS]
            
            # Look for ClientHello
            if not hasattr(tls_layer, 'msg') or not tls_layer.msg:
                return None
            
            for msg in tls_layer.msg:
                if isinstance(msg, TLSClientHello):
                    return self._process_client_hello(msg, packet)
            
            return None
            
        except Exception as e:
            logger.debug(f"JA3 extraction error: {e}")
            return None
    
    def _process_client_hello(self, client_hello, packet) -> Dict:
        """Process ClientHello to generate JA3"""
        
        # 1. SSL/TLS Version
        version = client_hello.version
        
        # 2. Cipher Suites
        ciphers = []
        if hasattr(client_hello, 'ciphers'):
            ciphers = [str(c) for c in client_hello.ciphers]
        
        # 3. Extensions
        extensions = []
        if hasattr(client_hello, 'ext'):
            extensions = [str(ext.type) for ext in client_hello.ext if hasattr(ext, 'type')]
        
        # 4. Elliptic Curves (Supported Groups)
        elliptic_curves = []
        elliptic_curve_point_formats = []
        
        if hasattr(client_hello, 'ext'):
            for ext in client_hello.ext:
                # Supported Groups extension (type 10)
                if hasattr(ext, 'type') and ext.type == 10:
                    if hasattr(ext, 'groups'):
                        elliptic_curves = [str(g) for g in ext.groups]
                
                # EC Point Formats extension (type 11)
                if hasattr(ext, 'type') and ext.type == 11:
                    if hasattr(ext, 'ecpl'):
                        elliptic_curve_point_formats = [str(f) for f in ext.ecpl]
        
        # Build JA3 string
        ja3_string = f"{version}," \
                     f"{'-'.join(ciphers)}," \
                     f"{'-'.join(extensions)}," \
                     f"{'-'.join(elliptic_curves)}," \
                     f"{'-'.join(elliptic_curve_point_formats)}"
        
        # Generate MD5 hash
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        # Try to identify the client
        client_identification = self.ja3_database.get(ja3_string, "Unknown Client")
        
        return {
            'type': 'JA3',
            'fingerprint': ja3_hash,
            'raw_string': ja3_string,
            'identified_as': client_identification,
            'src_ip': packet[TCP].sport if packet.haslayer(TCP) else None,
            'dst_ip': packet[TCP].dport if packet.haslayer(TCP) else None,
            'sni': self._extract_sni(client_hello),
            'timestamp': packet.time if hasattr(packet, 'time') else None
        }
    
    def extract_ja3s(self, packet) -> Optional[Dict]:
        """
        Extract JA3S fingerprint from TLS ServerHello
        
        JA3S format: SSLVersion,Cipher,Extensions
        """
        try:
            if not packet.haslayer(TLS):
                return None
            
            tls_layer = packet[TLS]
            
            if not hasattr(tls_layer, 'msg') or not tls_layer.msg:
                return None
            
            for msg in tls_layer.msg:
                if isinstance(msg, TLSServerHello):
                    return self._process_server_hello(msg, packet)
            
            return None
            
        except Exception as e:
            logger.debug(f"JA3S extraction error: {e}")
            return None
    
    def _process_server_hello(self, server_hello, packet) -> Dict:
        """Process ServerHello to generate JA3S"""
        
        # 1. SSL/TLS Version
        version = server_hello.version
        
        # 2. Selected Cipher Suite (single)
        cipher = str(server_hello.cipher) if hasattr(server_hello, 'cipher') else ""
        
        # 3. Extensions
        extensions = []
        if hasattr(server_hello, 'ext'):
            extensions = [str(ext.type) for ext in server_hello.ext if hasattr(ext, 'type')]
        
        # Build JA3S string
        ja3s_string = f"{version},{cipher},{'-'.join(extensions)}"
        
        # Generate MD5 hash
        ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()
        
        return {
            'type': 'JA3S',
            'fingerprint': ja3s_hash,
            'raw_string': ja3s_string,
            'src_ip': packet[TCP].sport if packet.haslayer(TCP) else None,
            'dst_ip': packet[TCP].dport if packet.haslayer(TCP) else None,
            'timestamp': packet.time if hasattr(packet, 'time') else None
        }
    
    def _extract_sni(self, client_hello) -> Optional[str]:
        """Extract Server Name Indication (SNI) from ClientHello"""
        try:
            if hasattr(client_hello, 'ext'):
                for ext in client_hello.ext:
                    # SNI extension (type 0)
                    if hasattr(ext, 'type') and ext.type == 0:
                        if hasattr(ext, 'servernames') and ext.servernames:
                            return ext.servernames[0].servername.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"SNI extraction error: {e}")
        
        return None
    
    def analyze_fingerprint(self, fingerprint_data: Dict) -> Dict:
        """
        Analyze fingerprint for anomalies
        
        Returns:
            - is_known: Boolean
            - risk_score: 0-100
            - observations: List of notes
        """
        observations = []
        risk_score = 0
        
        if fingerprint_data['type'] == 'JA3':
            # Check if this is a known good client
            if fingerprint_data['identified_as'] == "Unknown Client":
                observations.append("Unknown client fingerprint")
                risk_score += 30
            
            # Check for uncommon cipher suites
            if 'NULL' in fingerprint_data['raw_string']:
                observations.append("NULL cipher detected - possible downgrade attack")
                risk_score += 50
            
            # Check for very old TLS versions
            if '769' in fingerprint_data['raw_string']:  # TLS 1.0
                observations.append("Outdated TLS 1.0 detected")
                risk_score += 20
        
        return {
            'is_known': fingerprint_data['identified_as'] != "Unknown Client",
            'risk_score': min(risk_score, 100),
            'observations': observations
        }


if __name__ == "__main__":
    # Test TLS fingerprinting
    logging.basicConfig(level=logging.INFO)
    
    from scapy.all import rdpcap
    
    fingerprinter = TLSFingerprinter()
    
    # Example: Load a PCAP and extract JA3
    # pcap = rdpcap("tls_traffic.pcap")
    # for packet in pcap:
    #     ja3 = fingerprinter.extract_ja3(packet)
    #     if ja3:
    #         print(f"JA3: {ja3['fingerprint']} - {ja3['identified_as']}")
    
    print("TLS Fingerprinter initialized")
