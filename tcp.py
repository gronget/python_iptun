import socket
from threading import Thread
import logging
import select
from . import tun, net




def src_addr(packet: bytes):
    """Extracts src_addr field from IP packet."""
    return '.'.join([str(n) for n in packet[12:16]])
def our_pack(packet):
    return '.'.join([str(n) for n in packet])
def dst_addr(packet: bytes):
    """Extracts src_addr field from IP packet."""
    return '.'.join([str(n) for n in packet[16:20]])    




class socket_addr_store:
    def __init__(self,sock,client_addr):
        self.sock = sock
        self.client_addr = client_addr

class Server:
    def __init__(self) -> None:
        
        self.inputs = []
        self.main_sock = []
        self.outputs = []
        
        self.message_que = {}
        self.next_sendsock = {}
        self.sock_monitor = {}
        self.client_store ={}
        self.online_client_sock = {}
        self.online_client = []
        
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', 9090))
        self.server.listen(100)
        self.inputs.append(self.server)
        self.main_sock.append(self.server)


        
        self.byte_buffer = b''
        self.new_msg = True

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
            readable, writable, exceptional = select.select(self.inputs, self.outputs, [],0)
            for s in readable:
                if s in self.main_sock:
                    connection, client_address = s.accept()
                    connection.setblocking(False)
                    self.inputs.append(connection)
                   
                else:
                    try:
                        data = s.recv(4096)
                    except Exception as e: 
                        pass      
                    else:
                        '''
                        Since tcp streams data, we read every received chunk and extract the bytes length
                        (attached by client). Bytes with incomplete length are buffered waiting next chunk
                        
                        '''
                        if data:
                            if self.new_msg:
                                read_length = int(data[:7])
                                calc_lenght = len(data[7:])
                                if read_length == calc_lenght:
                                    self.on_pack2(data[7:],s)
                                    self.new_msg = True
                                elif calc_lenght > read_length:
                                    r_l = read_length
                                    c_l = calc_lenght
                                    while c_l >= r_l:
                                        data = data[7:]
                                        fetch_pack = data[:r_l]
                                        self.on_pack2(fetch_pack,s)
                                        data = data[r_l:]
                                        if data:
                                            r_l = int(data[:7])
                                            c_l = len(data[7:])
                                        else:
                                            break    
                                    if data:
                                        self.byte_buffer+=data
                                        self.new_msg = False
                                    else:
                                        self.new_msg=True    
                                elif calc_lenght < read_length:
                                    self.byte_buffer+=data
                                    self.new_msg = False
                            else:
                                self.byte_buffer+=data 
                                read_lenght = int(self.byte_buffer[:7])
                                calc_lenght = len(self.byte_buffer[7:])
                                if read_lenght == calc_lenght:
                                    self.on_pack2(self.byte_buffer[7:],s)
                                    self.new_msg = True
                                elif calc_lenght > read_lenght:
                                    r_l2 = read_lenght
                                    c_l2 = calc_lenght
                                    while c_l2 >= r_l2:
                                        self.byte_buffer = self.byte_buffer[7:]
                                        fetch_pack = self.byte_buffer[:r_l2]
                                        self.on_pack2(fetch_pack,s)
                                        self.byte_buffer = self.byte_buffer[r_l2:]
                                        if self.byte_buffer:
                                            r_l2 = int(self.byte_buffer[:7])
                                            c_l2 = len(self.byte_buffer[7:])
                                        else:
                                            break
                                    if self.byte_buffer:
                                        self.new_msg = False
                                    else:
                                        self.new_msg = True
                                elif calc_lenght < read_lenght:
                                    self.new_msg = False    
                        
                        else:
                            try:
                                del self.client_store[s]
                            except Exception as e:
                                print(e)
                            if s in self.inputs:
                                self.inputs.remove(s)
                            s.close()


    
    def on_tun_recv2(self) -> None:
        '''
        continously read from virtual Device attach packet length 
        and send to client (behave like udp like)
        '''
        while True:
            packet = self._tun_dev.read()
            if packet:
                logging.debug('tun0 recv: %s', packet)
                print(f"{dst_addr(packet)} ")
                print(f"lenght of packet {len(packet)} ")
                dst_ip_add = dst_addr(packet)
                if dst_ip_add in self.online_client:
                    sock = self.online_client_sock[dst_ip_add]
                    
                    packet_length = f"{len(packet):<7}".encode()
                    try:
                        sock.sendall(packet_length+packet)
                    except:
                        pass
    
    def on_pack2(self,packet:bytes,s) ->None:
        '''
        Client will send a normal packet from the virtual interface,
        authenticating packet or a deauth. A normal packet, we write to server virtual interface
        we assign a client an address from the ip pool
        '''
        if packet:
            x = packet[0]
            if x not in (48,49):
                print("normal pack")
                # online clients can access the server
                src_ip = src_addr(packet)
                if src_ip in self.online_client:
                    self.online_client_sock[src_ip] = s
                    self._tun_dev.write(packet)
                 
            elif x == 48:
                print("its auth")
                # we auth the client and provide an address
                shared_secret = packet.decode()[1:]
                print(shared_secret)
                new_tun_ip = self._addr_allocator.new(shared_secret)
                mtu = "m,1500"
                add_adr = f"a,{str(new_tun_ip)},24"
                add_route = "r,0.0.0.0,0"
                add_dns = "d,8.8.8.8"
                add_search_domain = "s,dns.google.com"
                client_auth = f"{mtu} {add_adr} {add_route} {add_dns} {add_search_domain}".encode()
                client_auth_append = b'0'+client_auth
                self.online_client.append(new_tun_ip)
                
                s.sendall(client_auth_append)
                
            elif x == 49:
                print("its deauth") 
                # TO DO
                #we release the ip and offline the client               

