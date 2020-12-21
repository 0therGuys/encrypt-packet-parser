import glob
import dpkt # Not use in this time. Because dpkt occurs some error.

from log import logger
from scapy.all import rdpcap, Scapy_Exception

'''
    Sequential feature description: To get a sequantial feature from encrypted packet especailly Tor Browser.
    Sequential Feature:
        Source(Client PC) -> Destination(Website Server) : Positive 1 (1)
        Destination(Website Server) -> Source(Client PC) : Negative 1 (-1)
        Default tor cell size is 512. So if there is a Source to Destination packet size of 1024.
        Then the sequential feature is [1, 1]
'''


class DpktSequantialFeature:

    def __init__(self, pcap_path, source_ip, tor_cell_size=512):
        '''
            @pcap_path: pcap file path
            @source_ip: client pc ip address (string or list)
            @tor_cell_size: tor cell size default is 512 bytes.
        '''
        assert pcap_path is not None or source_ip is not None

        self.pcap_path = pcap_path
        self.source_ip = source_ip
        self.tor_cell_size = tor_cell_size

    def parse_packet(self):
        logger.info('Parse %s pcap file' % self.pcap_path)
        pcap = dpkt.pcap.Reader(open(self.pcap_path, 'rb'))

        try:
            # We only use IP/TCP Layer packet because Tor use IP/TCP Layer.
            for i, (time_stamp, buffer) in enumerate(pcap):
                ethernet_layer = dpkt.ethernet.Ethernet(buffer)

                if not isinstance(ethernet_layer.data, dpkt.ip.IP):
                    logger.info('Non IP Packet type not supported %s, %d\'s packet in %s file' % (ethernet_layer.data.__class__.__name__, i, self.pcap_path))
                    continue
                ip_layer = ethernet_layer.data

                if not isinstance(ip_layer.data, dpkt.tcp.TCP):
                    logger.info('Non TCP Packet type not supported %s, %d\'s packet in %s file' % (ip_layer.data.__class__.__name__, i, self.pcap_path))
                    continue

        except AttributeError:
            logger.error('Attribute error occurs when parse %s pcap file.' % self.pcap_path)
            return None

        except dpkt.dpkt.UnpackError:
            logger.error('Unpack error occurs when parse %s pcap file.' % self.pcap_path)
            return None


class SequentialFeature:

    def __init__(self, pcap_path, source_ip, tor_cell_size=512):
        assert pcap_path is not None or source_ip is not None

        self.pcap_path = pcap_path
        self.source_ip = source_ip
        self.tor_cell_size = tor_cell_size
        self.feature_list = list()

    def _check_cell_size(self, packet):
        if self.tor_cell_size > int(packet):
            return True
        return False

    def _remainder_is_zero(self, packet):
        if int(packet) // self.tor_cell_size == 0:
            return True
        return False

    def parse_packet(self):
        logger.info('Parse %s pcap file' % self.pcap_path)
        pcap = rdpcap(self.pcap_path)
        try:
            for packet in pcap:

                if not packet.haslayer('IP') or not packet.haslayer('TCP'):
                    # Skip if packet don't have IP or TCP layer
                    continue

                if not packet('IP').src == self.source_ip or not packet('IP').dst == self.source_ip:
                    # Skip if packet don't related with Client PC & Web server.
                    continue

                if packet('IP').src == self.source_ip: # IP's src is Client PC
                    if self._check_cell_size(len(packet)) is True:
                        self.feature_list.append(1)
                    else:
                        if self._remainder_is_zero(len(packet)) is True:
                            for _ in range(int(len(packet)) // self.tor_cell_size):
                                self.feature_list.append(1)
                        else:
                            for _ in range(int(len(packet)) // self.tor_cell_size + 1):
                                self.feature_list.append(1)
                else: # IP's src is Web server
                    if self._check_cell_size(len(packet)) is True:
                        self.feature_list.append(-1)
                    else:
                        if self._remainder_is_zero(len(packet)) is True:
                            for _ in range(int(len(packet)) // self.tor_cell_size):
                                self.feature_list.append(-1)
                        else:
                            for _ in range(int(len(packet)) // self.tor_cell_size + 1):
                                self.feature_list.append(-1)

        except Scapy_Exception:
            logger.error('Scapy Exception when parse %s pcap file' % self.pcap_path)