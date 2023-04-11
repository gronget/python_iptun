import socket
import threading
from . import tun


def src_addr(packet: bytes)->str:
    """Extracts src_addr field from IP packet."""
    return '.'.join([str(n) for n in packet[12:16]])
def our_pack(packet:bytes)->str:
    return '.'.join([str(n) for n in packet])
def dst_addr(packet: bytes)->str:
    """Extracts src_addr field from IP packet."""
    return '.'.join([str(n) for n in packet[16:20]])    
 

def main()->None:
    # lets get tunnel ip 
    server_port_range = 9090
    packt = b'0sharedsecret1'
    auth = 0
    our_tunnel_ip = None

    while auth==0:
        auth_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        auth_sock.settimeout(15)#we wait for atmost 15secs before we try again
        server_add = ('192.168.0.164',server_port_range)
        try:
            print("Connecting to server")
            auth_sock.connect(server_add)
        except socket.timeout:
            print("timeout while conecting")
            auth_sock.close()
        else:
            try:
                packet_length = f"{len(packt):<7}".encode()
                auth_sock.sendall(packet_length+packt)
                print("Authenticating with server")
            except Exception as e:
                print(f"Auth error {e} ")
            else:
                try:
                    packtt = auth_sock.recv(4096)
                    print("recv data")
                    if packtt:
                        tun_int = packtt.decode()[1:]
                        print(tun_int)
                        print("Now here")
                        tun_int_array = tun_int.split(" ")
                        #loop through the array to get address
                        for la in tun_int_array:
                            if la[0] == 'a':
                                split_la = la.split(",")
                                vpn_add = split_la[1]
                                our_tunnel_ip = vpn_add
                                print( f"connection success, our ip is {our_tunnel_ip} ")
                        auth_sock.close()
                except socket.timeout:
                    auth_sock.close() 
                else:
                    auth_sock.close()
                    print("close socket")
                    auth = 1     
            
    print("Done with auth")
    tun_dev = tun.Device('tun1', our_tunnel_ip)
    tun_dev.up()

    protd = server_port_range
    server_add = ('192.168.0.164',protd)
    sockk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sockk.connect(server_add)
    except Exception as e:
        print(f"Error connecting to server {e} ")    



    rcv_thread = threading.Thread(target=recv_pack,args=(sockk,tun_dev,))
    rcv_thread.start()
    while True:
        packets = tun_dev.read()
        try:
            if src_addr(packets) == our_tunnel_ip:
                packet_lenght = f"{len(packets):<7}".encode()
                sockk.sendall(packet_lenght+packets)
                
        except Exception as e:
            print(f"Error sending packets {e} ")
       
def recv_pack(sockk,tun_dev)->None:
    byte_buffer = b''
    new_msg = True
    while True:
        try:
            data = sockk.recv(4096)
        except Exception as e:
            print(f"error on recv {e} ")
        else:
            if data:
                if new_msg:
                    read_length = int(data[:7])
                    calc_lenght = len(data[7:])
                    if read_length == calc_lenght:
                        tun_dev.write(data[7:])
                        new_msg = True
                    elif calc_lenght > read_length:
                        r_l = read_length
                        c_l = calc_lenght
                        while c_l >= r_l:
                            data = data[7:]
                            fetch_pack = data[:r_l]
                            tun_dev.write(fetch_pack)
                            data = data[r_l:]
                            if data:
                                r_l = int(data[:7])
                                c_l = len(data[7:])
                            else:
                                break    
                        if data:
                            byte_buffer+=data
                            new_msg = False
                        else:
                            new_msg=True    
                    elif calc_lenght < read_length:
                        byte_buffer+=data
                        new_msg = False
                else:
                    byte_buffer+=data 
                    read_lenght = int(byte_buffer[:7])
                    calc_lenght = len(byte_buffer[7:])
                    if read_lenght == calc_lenght:
                        tun_dev.write(byte_buffer[7:])
                        new_msg = True
                    elif calc_lenght > read_lenght:
                        r_l2 = read_lenght
                        c_l2 = calc_lenght
                        while c_l2 >= r_l2:
                            byte_buffer = byte_buffer[7:]
                            fetch_pack = byte_buffer[:r_l2]
                            tun_dev.write(fetch_pack)
                            byte_buffer = byte_buffer[r_l2:]
                            if byte_buffer:
                                r_l2 = int(byte_buffer[:7])
                                c_l2 = len(byte_buffer[7:])
                            else:
                                break
                        if byte_buffer:
                            new_msg = False
                        else:
                            new_msg = True
                    elif calc_lenght < read_lenght:
                        new_msg = False
   

if __name__ == '__main__':
    main()
    





