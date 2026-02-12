from parser import NmapParser
import json
import os
from datetime import datetime
from os import PathLike
from pathlib import Path
from pprint import pprint
from typing import Iterator

from sortedcontainers import SortedDict

from embedder import Embedder


class Comparator:
    def __init__(self, embedder: Embedder, data_path: str | PathLike):
        self.embedder = embedder
        self.time_to_hosts = self._load_data(data_path)

    def _load_data(self, path: str | PathLike):
        data_iter = Path(path).glob("*.json")
        time_to_file = self._parse_datetime(data_iter)
        time_to_hosts = SortedDict()
        for time, file in time_to_file.items():
            with open(file) as f:
                hosts = json.load(f)
                time_to_hosts[time] = hosts
        time_to_hosts = {
            time: self._normalise(host) for time, host in time_to_hosts.items()
        }

    def _parse_datetime(self, paths: Iterator[Path]) -> dict[datetime, str]:
        out = SortedDict()
        for path in paths:
            name = os.path.basename(path)
            timestamp_str = name.replace("scan_", "").replace(".json", "")
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d_%H-%M-%S")
            out[dt] = path
        return out

    @staticmethod
    def _normalise(hosts):
        out = []
        for host in hosts:
            parser = NmapParser(host)
            out.append(parser.parse())
        return out


if __name__ == "__main__":
    embedder = Embedder("all-minilm:22m")
    c = Comparator(embedder, "./data/")
    c._load_data("./data/")
