import socket
import os

# host to listen on
host = "0.0.0.0"


# create a raw socket and bind it to the public interface
# The difference between Windows and Linux is that Windows will allow us to
# sniff all incoming packets regardless of protocol, whereas Linux forces us to specify that we are
# sniffing ICMP.
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# we want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we are using Windows, we need to send an IOCTL (socket input/output control)
# to set up promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
# read in a single packet
print sniffer.recvfrom(65565)

# if we are using Windows, turn off promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)