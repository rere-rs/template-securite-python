from scapy.all import get_if_list

def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice
    """
    interfaces = get_if_list()
    print("[*] Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")
    choice = int(input("Select interface number: "))
    return interfaces[choice]
