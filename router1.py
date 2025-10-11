import socket
import sys
import time
import os
import glob


# Helper Functions

# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    # 1. Create a socket.
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 2. Try connecting the socket to the host and port.
    try:
        soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    # 3. Return the connected socket.
    return soc


# The purpose of this function is to read in a CSV file.
def read_csv(path):
    # 1. Open the file for reading.
    table_file = open(path, "r")
    # 2. Store each line.
    table = table_file.readlines()
    # 3. Create an empty list to store each processed row.
    table_list = []
    # 4. For each line in the file:
    for line in table:
        # 5. split it by the delimiter,
        split_line = line.split(",")
        # 6. remove any leading or trailing spaces in each element, and
        processed_line = []
        for element in split_line:
            processed_line.append(element.strip())
        # 7. append the resulting list to table_list.
        table_list.append(processed_line)
    # 8. Close the file and return table_list.
    table_file.close()
    return table_list


# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
def find_default_gateway(table):
    # 1. Traverse the table, row by row,
    for row in table:
        # 2. and if the network destination of that row matches 0.0.0.0,
        if row[0] == "0.0.0.0":
            # 3. then return the interface of that row.
            return row[3]


# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    # 1. Create an empty list to store the new forwarding table.
    new_table = []
    # 2. Traverse the old forwarding table, row by row,
    for row in table:
        # 3. and process each network destination other than 0.0.0.0
        # (0.0.0.0 is only useful for finding the default port).
        if row[0] != "0.0.0.0":
            # 4. Store the network destination and netmask.
            network_dst_string = row[0]
            netmask_string = row[1]
            # 5. Convert both strings into their binary representations.
            network_dst_bin = ip_to_bin(network_dst_string)
            netmask_bin = ip_to_bin(netmask_string)
            # 6. Find the IP range.
            ip_range = find_ip_range(network_dst_bin, netmask_bin)
            # 7. Build the new row.
            new_row = [network_dst_string, netmask_string, row[2], ip_range]
            # 8. Append the new row to new_table.
            new_table.append(new_row)
    # 9. Return new_table.
    return new_table


# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    # 1. Split the IP into octets.
    ip_octets = ip.split('.')
    # 2. Create an empty string to store each binary octet.
    ip_bin_string = ""
    # 3. Traverse the IP, octet by octet,
    for octet in ip_octets:
        # 4. and convert the octet to an int,
        int_octet = int(octet)
        # 5. convert the decimal int to binary,
        bin_octet = bin(int_octet)
        # 6. convert the binary to string and remove the "0b" at the beginning of the string,
        bin_octet_string = bin_octet[2:]
        # 7. while the sting representation of the binary is not 8 chars long,
        # then add 0s to the beginning of the string until it is 8 chars long
        # (needs to be an octet because we're working with IP addresses).
        while len(bin_octet_string) != 8:
            bin_octet_string = "0" + bin_octet_string
        # 8. Finally, append the octet to ip_bin_string.
        ip_bin_string = ip_bin_string + bin_octet_string
    # 9. Once the entire string version of the binary IP is created, convert it into an actual binary int.
    return int(str(ip_bin_string), 2)


# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst, netmask):
    # 1. Perform a bitwise AND on the network destination and netmask
    # to get the minimum IP address in the range.
    bitwise_and = network_dst & netmask
    # 2. Perform a bitwise NOT on the netmask
    # to get the number of total IPs in this range.
    # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
    # we need to create our own bitwise NOT operator for our unsigned int (a netmask).
    compliment = bit_not(netmask)
    min_ip = bitwise_and
    # 3. Add the total number of IPs to the minimum IP
    # to get the maximum IP address in the range.
    max_ip = min_ip + compliment
    # 4. Return a list containing the minimum and maximum IP in the range.
    return [min_ip, max_ip]


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    # 1. Open the output file for appending.
    out_file = open(path, "a")
    # 2. If this router is not sending, then just append the packet to the output file.
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    # 3. Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    # 4. Close the output file.
    out_file.close()


# Main Program

# 0. Remove any output files in the output directory
# (this just prevents you from having to manually delete the output files before each run).
files = glob.glob('./output/*')
for f in files:
    os.remove(f)

THIS_ROUTER_ID = "1"

HOST = "127.0.0.1"

port_map = {
    "2": 8002,
    "4": 8004,
}

SENT_FILE = f"./output/sent_by_router_{THIS_ROUTER_ID}.txt"
OUT_FILE = f"./output/out_router_{THIS_ROUTER_ID}.txt"
DISCARD_FILE = f"./output/discarded_by_router_{THIS_ROUTER_ID}.txt"


# 1. Connect to the appropriate sending ports (based on the network topology diagram).

sockets = {}
for interface, port in port_map.items():
    try:
        soc = create_socket(HOST, port)
        sockets[interface] = soc
        print(f"Connected to Router {interface} on port {port}")
    except SystemExit:
        sockets[interface] = None
    except Exception as e:
        print(f"Could not connect to Router {interface} : {e}")
        sockets[interface] = None

# 2. Read in and store the forwarding table.
forwarding_table = read_csv("./router1_table.csv")
# 3. Store the default gateway port.
default_gateway_port = find_default_gateway(forwarding_table)
# 4. Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)
# 5. Read in and store the packets.
packets_table = read_csv("packets.csv")

if not os.path.isdir("./output"):
    os.makedirs("./output")

# 6. For each packet,
for packet in packets_table:

    if len(packet) < 4:
        continue

    # 7. Store the source IP, destination IP, payload, and TTL.
    sourceIP = packet[0]
    destinationIP = packet[1]
    payload = packet[2]
    try:
        ttl = int(packet[3])
    except:
        ttl = 0

    # 8. Decrement the TTL by 1 and construct a new packet with the new TTL.
    new_ttl = ttl - 1
    new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"

    # 9. Convert the destination IP into an integer for comparison purposes.
    try:
        destinationIP_bin = ip_to_bin(destinationIP)
    except Exception:
        print("DISCARD (bad IP):", new_packet)
        write_to_file(DISCARD_FILE, new_packet)
        time.sleep(1)
        continue

    # 9. Find the appropriate sending port to forward this new packet to.
    sending_port = None
    for row in forwarding_table_with_range:
        ip_range = row[3]
        if ip_range[0] <= destinationIP_bin <= ip_range[1]:
            sending_port = row[2]
            break

    if sending_port is None:
        sending_port = default_gateway_port

    if new_ttl <= 0:
        print("DISCARD:", new_packet)
        write_to_file(DISCARD_FILE, new_packet)
        time.sleep(1)
        continue

    if sending_port == THIS_ROUTER_ID:
        print("OUT:", payload)
        write_to_file(OUT_FILE, payload)

    elif sending_port in sockets and sockets[sending_port] is not None:
        print(f"Sending packet {new_packet} to Router {sending_port}")
        try:
            sockets[sending_port].sendall(new_packet.encode())
        except Exception as e:
            print(f"Socket send failed to Router {sending_port}: {e}")
        write_to_file(SENT_FILE, new_packet, send_to_router=sending_port)

    else:
        print("DISCARD:", new_packet)
        write_to_file(DISCARD_FILE, new_packet)

    time.sleep(1)

for s in sockets.values():
    try:
        if s:
            s.close()
    except:
        pass