from scapy.all import sniff, DNSQR, conf
import ifaddr
from random import choice

reset = "\033[0m"
neon_red = "\033[38;2;255;0;85m"
banner = rf"""{neon_red}  
                      __       .___             
______   ____   ____ |  | __ __| _/____   ______
\____ \_/ __ \_/ __ \|  |/ // __ |/    \ /  ___/
|  |_> >  ___/\  ___/|    </ /_/ |   |  \\___ \ 
|   __/ \___  >\___  >__|_ \____ |___|  /____  >
|__|        \/     \/     \/    \/    \/     \/ 
{reset}
"""


def colourSelect():
    colors = {
        "neon_red": "\033[38;2;255;0;85m",
        "neon_pink": "\033[38;2;255;20;147m",
        "neon_magenta": "\033[38;2;255;0;255m",
        "neon_purple": "\033[38;2;170;0;255m",
        "neon_blue": "\033[38;2;0;120;255m",
        "neon_cyan": "\033[38;2;0;255;255m",
        "neon_green": "\033[38;2;57;255;20m",
        "neon_lime": "\033[38;2;192;255;0m",
        "neon_yellow": "\033[38;2;255;255;0m",
        "neon_orange": "\033[38;2;255;120;0m",
    }
    return choice(list(colors.values()))


conf.use_pcap = True


def proccess_packets(packet):
    reset = "\033[0m"
    if packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            colour = colourSelect()
            print(f"[+] DNS query [=] {colour} {domain} {reset} [=]")
        except Exception:
            pass


def main():
    print(banner)
    adapters = list(ifaddr.get_adapters())
    print("=" * 15)
    for i, adapter in enumerate(adapters, start=1):
        print(f"[+] Interface {i}: {adapter.nice_name}")
    print("=" * 15)

    try:
        choice = int(input("Please select an interface's number: "))
        interface = adapters[choice - 1]
    except (ValueError, IndexError):
        print("Invalid option")
        return

    ip = input("What IP addr to listen for: ")
    print(f"\nListening on {interface.nice_name}")
    sniff(
        iface=interface.nice_name,
        filter=f"port 53 and host {ip}",
        store=False,
        prn=proccess_packets,
    )


if __name__ == "__main__":
    main()
