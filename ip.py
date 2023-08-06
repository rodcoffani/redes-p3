from iputils import *
from ipaddress import ip_address, ip_network, IPv4Address


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        # Constroi um objeto ip_address a partir da string dest_addr
        dst_address = ip_address(dest_addr)

        for cidr, next_hop in self.tabela:
            # Constroi um objeto ip_network a partir da string cidr 
            net = ip_network(cidr)

            # Verifica se o endereço de destino de destino está na rede
            if dst_address in net:
                return next_hop

        # Se não encontrar o next_hop, retorna None
        return None
            

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.

        # Tabela de encaminhamento
        self.tabela = tabela
        
        return

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        # Variáveis do cabeçalho
        version = 4
        ihl = 5
        dscp = 0
        ecn = 0
        total_length = 20 + len(segmento)
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0        
        
        # Endereços de origem e destino
        src_addr = IPv4Address(self.meu_endereco)
        dest_address = IPv4Address(dest_addr)

        # Monta o cabeçalho
        header = (
            (version << 4) + ihl,
            (dscp << 2) + ecn,
            total_length,
            identification,
            (flags << 13) + frag_offset,
            ttl,
            proto,
            checksum,
            int(src_addr),
            int(dest_address)
        )

        # Monta o datagrama
        packed_header = struct.pack('!BBHHHBBHII', *header)

        # Calcula o checksum
        checksum = calc_checksum(packed_header)
        header = (
            (version << 4) + ihl,
            (dscp << 2) + ecn,
            total_length,
            identification,
            (flags << 13) + frag_offset,
            ttl,
            proto,
            checksum,
            int(src_addr),
            int(dest_address)
        )

        # Monta o datagrama (de novo, agora com o checksum)
        packed_header = struct.pack('!BBHHHBBHII', *header)

        datagrama = packed_header + segmento

        self.enlace.enviar(datagrama, next_hop)
