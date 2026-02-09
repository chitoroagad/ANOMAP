import logging
from typing import NamedTuple


class PortsInfo(NamedTuple):
    services: dict[int, str]
    open_ports: list[int]


class PortInfo(NamedTuple):
    portid: int
    service: str
    open_port: bool


class NmapParser:
    def __init__(self, host_data: dict):
        self.raw_data = host_data
        self.normalised_data = {}

    def parse(self):
        self._extract_os_data()
        self._extract_device_vendor()
        self._extract_ports()

    def _first_item(self, val: dict | list) -> dict:
        if isinstance(val, list):
            return val[0] if val else None
        return val

    def _extract_os_data(self):
        os_data = self.raw_data.get("os")
        if not os_data:
            logging.warning("No 'os' key in input data")
        else:
            osmatch: dict = self._first_item(os_data.get("osmatch"))
            if not osmatch:
                logging.warning("No 'osmatch' key in host_data['os']")
            else:
                osclass: dict = self._first_item(osmatch.get("osclass"))
                if not osclass:
                    logging.warning("No 'osclass' key in host_data['os']['osmatch']")
                else:
                    self.normalised_data.update(
                        {
                            "os": osclass.get("@vendor")
                            if osclass.get("@vendor")
                            else osclass.get("@osfamily"),
                            "os_type": osclass.get("@type"),
                            "os_version": osclass.get("@osgen"),
                            "distribution": osmatch.get("@name"),
                        }
                    )

    def _extract_device_vendor(self):
        address = self.raw_data.get("address")
        if not address:
            logging.warning("No 'address' key in input data")
        else:
            vendor = self._find_device_vendor(address)
        self.normalised_data["device_vendor"] = vendor

    def _find_device_vendor(self, address):
        address_iter = address if isinstance(address, list) else [address]
        for addr in address_iter:
            vendor = self._check_address(addr)
            if not vendor:
                continue
            return vendor

    def _check_address(self, addr: dict):
        addrtype = addr.get("@addrtype")
        vendor = None
        if not addrtype:
            logging.warning(f"No '@addrtype' in address: {addr}")
            return None

        if addrtype == "mac":
            vendor = addr.get("@vendor")
            if not vendor:
                logging.warning(f"No '@vendor' key in mac address: {addr}")

        return vendor

    def _extract_ports(self):
        # excludes the "extra ports" field
        ports = self.raw_data.get("ports")
        if not ports:
            logging.warning("No 'ports' field found in input data")
            return
        ports_list = ports.get("port")
        if not ports_list:
            logging.warning("No 'port' field found in ports map")
            return

        open_ports, services = self._find_ports(ports_list)
        self.normalised_data.update({"open_ports": open_ports, "services": services})

    def _find_ports(self, ports: dict | list) -> PortsInfo:
        open_ports = []
        services = {}

        ports_iter = ports if isinstance(ports, list) else [ports]
        for port in ports_iter:
            portid, service, port_open = self._check_port(port)
            if not portid:
                logging.warning("Skipped a port with no portid")
                continue

            services[portid] = service
            if port_open:
                open_ports.append(portid)

        return PortsInfo(open_ports, services)

    def _check_port(self, port) -> PortInfo:
        portid = port.get("@portid")
        if not portid:
            logging.warning(f"No '@portid' found for port: {port}")

        state_map = port.get("state")
        state = None
        if state_map:
            state = state_map.get("@state")
        if not state:
            logging.warning(f"No 'state' found for port: {portid}")

        service_map = port.get("service")
        service_name = ""
        service_product = ""
        service = None
        if service_map:
            service_name = service_map.get("@name")
            service_product = service_map.get("@product")
            if service_name and service_product:
                service = service_name + "-" + service_product
            else:
                service = service_name if service_name else service_product
        if not service:
            logging.warning(f"No 'service' found for port: {portid}")

        open_port = False
        if state == "open":
            open_port = True
        return PortInfo(portid, service, open_port)
