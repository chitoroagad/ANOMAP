import pytest
from unittest.mock import MagicMock
from peerwatch.parser import NmapParser, NormalisedData


class TestNmapParser:
    def test_parse_minimal_host_data(self):
        host_data = {
            "os": {
                "osmatch": [
                    {
                        "osclass": [
                            {
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "5.4",
                                "@type": "general purpose",
                            }
                        ],
                        "@name": "Ubuntu",
                    }
                ]
            },
            "address": [
                {"@addr": "00:11:22:33:44:55", "@addrtype": "mac", "@vendor": "Apple"},
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
            "ports": {
                "port": [
                    {
                        "@portid": "22",
                        "state": {"@state": "open"},
                        "service": {"@name": "ssh", "@product": "OpenSSH"},
                    },
                    {
                        "@portid": "80",
                        "state": {"@state": "open"},
                        "service": {"@name": "http", "@product": "Apache"},
                    },
                ]
            },
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert result.mac_address == "00:11:22:33:44:55"
        assert result.ipv4 == "192.168.1.1"
        assert result.os == "Linux"
        assert result.os_version == "5.4"
        assert 22 in result.open_ports
        assert 80 in result.open_ports
        assert result.services[22] == "ssh-OpenSSH"
        assert result.services[80] == "http-Apache"

    def test_parse_ipv6_address(self):
        host_data = {
            "address": [
                {"@addr": "2001:db8::1", "@addrtype": "ipv6"},
            ],
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert result.ipv6 == "2001:db8::1"

    def test_parse_with_no_ports(self):
        host_data = {
            "address": [
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert result.ipv4 == "192.168.1.1"
        assert result.open_ports == []

    def test_parse_with_missing_os_data(self):
        host_data = {
            "address": [
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
            "ports": {
                "port": [
                    {
                        "@portid": "22",
                        "state": {"@state": "open"},
                        "service": {"@name": "ssh"},
                    }
                ]
            },
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert result.os == "unknown"
        assert result.device_vendor == "unknown"

    def test_parse_multiple_addresses_vendor_priority(self):
        host_data = {
            "address": [
                {"@addr": "00:11:22:33:44:55", "@addrtype": "mac"},
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert result.device_vendor == "unknown"

    def test_parse_closed_ports_excluded(self):
        host_data = {
            "address": [
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
            "ports": {
                "port": [
                    {
                        "@portid": "22",
                        "state": {"@state": "open"},
                        "service": {"@name": "ssh"},
                    },
                    {
                        "@portid": "80",
                        "state": {"@state": "closed"},
                        "service": {"@name": "http"},
                    },
                ]
            },
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert 22 in result.open_ports
        assert 80 not in result.open_ports

    def test_parse_single_port_list(self):
        host_data = {
            "address": [
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
            "ports": {
                "port": {
                    "@portid": "22",
                    "state": {"@state": "open"},
                    "service": {"@name": "ssh"},
                }
            },
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert 22 in result.open_ports

    def test_parse_os_candidates_populated(self):
        host_data = {
            "os": {
                "osmatch": [
                    {
                        "@name": "OpenWrt 21.02",
                        "@accuracy": "96",
                        "osclass": {
                            "@vendor": "Linux",
                            "@osfamily": "Linux",
                            "@osgen": "5.X",
                        },
                    },
                    {
                        "@name": "Android 10",
                        "@accuracy": "93",
                        "osclass": [
                            {
                                "@vendor": "Google",
                                "@osfamily": "Android",
                                "@osgen": "10.X",
                            },
                            {"@vendor": "Linux", "@osfamily": "Linux", "@osgen": "4.X"},
                        ],
                    },
                ]
            },
            "address": [{"@addr": "192.168.1.1", "@addrtype": "ipv4"}],
        }

        result = NmapParser(host_data).parse()

        assert "Linux" in result.os_candidates
        assert "Google" in result.os_candidates
        assert result.os_candidates["Linux"] == 96  # max accuracy across both matches
        assert result.os_candidates["Google"] == 93
        assert result.os == "Linux"  # top pick unchanged

    def test_parse_os_candidates_best_accuracy_kept(self):
        # Linux appears in two matches at different accuracies — keep the higher one
        host_data = {
            "os": {
                "osmatch": [
                    {
                        "@name": "Match A",
                        "@accuracy": "90",
                        "osclass": {"@vendor": "Linux", "@osfamily": "Linux"},
                    },
                    {
                        "@name": "Match B",
                        "@accuracy": "95",
                        "osclass": {"@vendor": "Linux", "@osfamily": "Linux"},
                    },
                ]
            },
            "address": [{"@addr": "192.168.1.1", "@addrtype": "ipv4"}],
        }

        result = NmapParser(host_data).parse()
        assert result.os_candidates["Linux"] == 95

    def test_parse_uses_os_vendor_over_osfamily(self):
        host_data = {
            "os": {
                "osmatch": [
                    {
                        "osclass": [
                            {
                                "@vendor": "Apple",
                                "@osfamily": "Linux",
                                "@osgen": "18.04",
                            }
                        ],
                    }
                ]
            },
            "address": [
                {"@addr": "192.168.1.1", "@addrtype": "ipv4"},
            ],
        }

        parser = NmapParser(host_data)
        result = parser.parse()

        assert result.os == "Apple"
