import socket
import struct
import argparse
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Monitors TCP connections for abnormal resets (RST packets).")

    # Add arguments for filtering connections
    parser.add_argument("--interface", "-i", type=str, default="eth0", help="Network interface to listen on (e.g., eth0, wlan0). Defaults to eth0.")
    parser.add_argument("--src_ip", type=str, help="Filter by source IP address (optional).")
    parser.add_argument("--dst_ip", type=str, help="Filter by destination IP address (optional).")
    parser.add_argument("--src_port", type=int, help="Filter by source port (optional).")
    parser.add_argument("--dst_port", type=int, help="Filter by destination port (optional).")
    parser.add_argument("--promiscuous", action="store_true", help="Enable promiscuous mode (requires root).")
    parser.add_argument("--log_file", type=str, help="Path to log file (optional).")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")

    return parser.parse_args()


def is_rst_packet(tcp_header):
    """
    Checks if a TCP packet is a reset (RST) packet.

    Args:
        tcp_header (bytes): The TCP header as a byte string.

    Returns:
        bool: True if the RST flag is set, False otherwise.
    """
    try:
        # Extract the flags field from the TCP header
        tcp_flags_offset = 13  # Offset of flags in TCP header
        tcp_flags = tcp_header[tcp_flags_offset]

        # Check if the RST flag is set (RST flag is the 4th bit, value 0x04 or 1 << 2)
        return (tcp_flags & 0x04) != 0  # Check the RST bit
    except IndexError:
        logging.error("TCP Header too short to extract flags.")
        return False
    except Exception as e:
        logging.error(f"Error processing TCP header: {e}")
        return False

def process_packet(packet, args):
    """
    Processes a raw network packet, checking for TCP RST packets and applying filters.

    Args:
        packet (bytes): The raw network packet as a byte string.
        args (argparse.Namespace): Command-line arguments.
    """
    try:
        # Ethernet Header (14 bytes)
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = struct.unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        # IP Header (minimum 20 bytes)
        if eth_protocol == 8:  # IPv4
            ip_header = packet[eth_length:eth_length+20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # TCP Packet
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)

                src_port = tcph[0]
                dst_port = tcph[1]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                # Apply filters
                if args.src_ip and s_addr != args.src_ip:
                    return
                if args.dst_ip and d_addr != args.dst_ip:
                    return
                if args.src_port and src_port != args.src_port:
                    return
                if args.dst_port and dst_port != args.dst_port:
                    return

                # Check for RST flag
                if is_rst_packet(tcp_header):
                    logging.warning(f"Detected TCP RST packet: Source IP: {s_addr}, Destination IP: {d_addr}, Source Port: {src_port}, Destination Port: {dst_port}")
                    if args.verbose:
                        logging.info(f"Full Packet: {packet}")
    except struct.error as e:
        logging.error(f"Struct error during packet processing: {e}. Packet might be incomplete.")
    except socket.error as e:
        logging.error(f"Socket error during packet processing: {e}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def main():
    """
    Main function to capture and process network packets.
    """
    args = setup_argparse()

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)  # Log everything if verbose is enabled
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(file_handler)

    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        # Bind to the specified interface
        sock.bind((args.interface, 0))

        # Enable promiscuous mode (if specified)
        if args.promiscuous:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PROMISC, 1)
            logging.info("Promiscuous mode enabled.")

        logging.info(f"Listening on interface {args.interface}...")

        while True:
            packet = sock.recv(65535)  # Receive packets
            process_packet(packet, args)

    except socket.error as msg:
        logging.error(f"Socket error: {msg}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Exiting...")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        if 'sock' in locals():
            sock.close()
            logging.info("Socket closed.")


if __name__ == "__main__":
    # Example Usage 1: Basic monitoring on eth0
    # python main.py -i eth0

    # Example Usage 2: Filter by source IP
    # python main.py --src_ip 192.168.1.100

    # Example Usage 3: Filter by destination port
    # python main.py --dst_port 80

    # Example Usage 4: Promiscuous mode with verbose logging to a file
    # python main.py -i eth0 --promiscuous --log_file rst_detector.log --verbose

    # Example Usage 5: Filter by source IP and Destination Port
    # python main.py --src_ip 192.168.1.100 --dst_port 80
    main()