import socket
# from struct import pack
from threading import Thread
import logging
import itertools
from typing import Tuple
import select
from IPy import IP
import os
# from Crypto.Cipher import AES
# from Crypto.Util import Counter

from . import tun, ip, net

# key=b'\xa32\xf8\xf6-\xf9M^\x82\xff\xb1\xc0\x97W\xf1d\t}\x1e\x82V\xbf\xe3\xab\xeb7 \x93\xbf\xfb\x8ah'
# nounce = os.urandom(8)
# nounce = b';\xa3\xf4gL\x973.'
# counterf = Counter.new(64,nounce)
# encrypt_key = AES.new(key, AES.MODE_CTR, counter=counterf)
# decrpt_key = AES.new(key, AES.MODE_CTR, counter=counterf)




class socket_addr_store:
    def __init__(self,sock,client_addr):
        self.sock = sock
        self.client_addr = client_addr

class Server:
    def __init__(self, bind_addr: str='0.0.0.0') -> None:
        self.online_client = []
        self.online_client_sock = {}
        self.reads = []
        self.writes = []
        
        for port in range(9093,9990):
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._addr = ('0.0.0.0', port)
            self._sock.setblocking(0)
            self._sock.bind(self._addr)
            self.reads.append(self._sock)
        self._threads = []
        self._tun_dev = None

        self._nat = net.NAT()
        self._addr_allocator = net.AddrAllocator('10.0.0.0/24')

    def route_traffic_to(self, tun_dev: tun.Device) -> 'Server':
        self._tun_dev = tun_dev
        return self

    def start(self) -> None:
        

        self._tun_read_thread = Thread(target=self.on_tun_recv2)
        self._tun_read_thread.start()

        while True:
            readeables,writeables,Exceptions=select.select(self.reads,self.writes,self.writes)
            for s in readeables:
                packet, addr = s.recvfrom(4096)
                # self.sock_monitor[addr[0]] = socket_addr_store(s,addr)
                new_thread = Thread(target=self.on_pack2, args=(packet, addr,s,))
                # self._threads.append(new_thread)
                new_thread.start()

    def on_tun_recv(self) -> None:
        while True:
            packet = bytearray(self._tun_dev.read())
            logging.debug('tun0 recv: %s', packet)
            print(f"{ip.src_addr(packet)} ")
            if ip.src_addr(packet) != "0.0.0.0":
                print(f"Now here were its not 0.0.0.0")
                client_addr = self._nat.in_(packet)
                if client_addr is not None:
                    sock = self.sock_monitor[client_addr[0]].sock
                    addr = self.sock_monitor[client_addr[0]].client_addr
                    logging.debug('conn send: %s', packet)
                    print(f"{client_addr} ")
                    # encrypt_key = AES.new(key, AES.MODE_CTR, counter=counterf)
                    # packet = encrypt_key.encrypt(packet)
                    sock.sendto(packet, addr)
                   
    def on_tun_recv2(self) -> None:
        while True:
            packet = self._tun_dev.read()
            logging.debug('tun0 recv: %s', packet)
            print(f"{ip.dst_addr(packet)} ")
            s_thread = Thread(target=self.send_pack2, args=(packet,))
            s_thread.start()
             

    def send_pack2(self,packet):

        dst_ip_add = ip.dst_addr(packet)
        if dst_ip_add in self.online_client:
            sock = self.online_client_sock[dst_ip_add].sock
            add = self.online_client_sock[dst_ip_add].client_addr
            sock.sendto(packet,add)                                   


    def on_pack2(self,packet:bytes,client_addr:net.Address,s) ->None:
        x = packet[0]
        if x not in (0,1):
            print("normal pack")
            # online clients can access the server
            src_ip = ip.src_addr(packet)
            print(src_ip)
            if src_ip in self.online_client:
                self.online_client_sock[src_ip] = socket_addr_store(s,client_addr)
                self._tun_dev.write(packet)
        elif x == 0:
            if len(packet) > 4:
                print("its auth")
                # we auth the client and provide an address
                
                shared_secret = packet.decode()[1:]
                print(shared_secret)
                new_tun_ip = self._addr_allocator.new(shared_secret)

                mtu = "m,1500"
                # add_adr = "a,10.0.0.1,24"
                add_adr = f"a,{str(new_tun_ip)},24"
                add_route = "r,0.0.0.0,0"
                add_dns = "d,8.8.8.8"
                add_search_domain = "s,dns.google.com"
                client_auth = f"{mtu} {add_adr} {add_route} {add_dns} {add_search_domain}".encode()
                # client_auth_append = b'0'+client_auth
                client_auth_append = b'\x00'+client_auth

                # packta = str(new_tun_ip).encode()
                self.online_client.append(new_tun_ip)
                s.sendto(client_auth_append,client_addr)
        elif x == 1:
            print("its deauth") 
            #we release the ip and offline the client       
