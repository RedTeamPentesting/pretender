#!/usr/bin/env python3

import csv
from dataclasses import dataclass
import datetime
import os.path
import re
import sys
from typing import Iterator, Sequence

import requests


OUTPUT_FILE = "mac-vendors.txt"

SOURCES = [
    "https://standards-oui.ieee.org/cid/cid.csv",
    "https://standards-oui.ieee.org/iab/iab.csv",
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
]

MAC_PREFIX_FIELD = 1
ORG_FIELD = 2

MAX_ORG_SIZE = 12
IGNORED_TERMS = [
    "gmbh",
    "inc",
    "llc",
    "a/s",
    "ag",
    "s.r.l",
    "ltd",
    "sa",
    "s.l",
    "co",
    "trading",
    "limited",
    "incorporated",
    "corporate",
    "corporation",
    "technologies",
    "technology",
]


@dataclass
class MacVendorEntry:
    mac_prefix: str
    vendor_short: str
    vendor: str

    @property
    def csv_line(self) -> tuple[str, str, str]:
        return (self.mac_prefix, self.vendor_short, self.vendor)


def all_mac_vendor_entries(urls: Sequence[str]) -> Iterator[MacVendorEntry]:
    for url in urls:
        print(f"Downloading {url}", file=sys.stderr)
        csv_data = download(url)

        print("  Processing...", file=sys.stderr)
        yield from mac_vendor_entries_from_csv(csv_data)


def mac_vendor_entries_from_csv(csv_content: str) -> Iterator[MacVendorEntry]:
    csv_reader = csv.reader(csv_content.splitlines(), delimiter=",", quotechar='"')
    next(csv_reader, None)  # skip headers

    for row in csv_reader:
        mac = process_mac_prefix(row[MAC_PREFIX_FIELD])
        short_org = shorten_org(row[ORG_FIELD])

        yield MacVendorEntry(
            mac_prefix=mac, vendor_short=short_org, vendor=row[ORG_FIELD]
        )


def process_mac_prefix(raw_mac: str) -> str:
    return ":".join([raw_mac[i : i + 2].upper() for i in range(0, len(raw_mac), 2)])


def shorten_org(org: str) -> str:
    org = org.strip()

    for term in IGNORED_TERMS:
        org = re.sub(
            f"[\\s\\W]({re.escape(term)})(?:[\\s\\W]|\\Z)", "", org, flags=re.IGNORECASE
        )

    return re.sub("[\\s\\W]", "", org)[:MAX_ORG_SIZE]


def download(url: str) -> str:
    res = requests.get(url)
    res.raise_for_status()

    return res.text


def main():
    mac_prefixes: set[str] = set()

    with open(OUTPUT_FILE, "w") as mac_file:
        mac_file.write(
            f"# The file was automatically generated "
            f"on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"by {os.path.basename(__file__)} via `go generate`\n"
        )

        csv_writer = csv.writer(
            mac_file, delimiter="\t", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )

        for mac_vendor_entry in all_mac_vendor_entries(SOURCES):
            if mac_vendor_entry.mac_prefix in mac_prefixes:
                print(
                    f"  Ignore duplicate entry: {mac_vendor_entry.mac_prefix} "
                    f"({mac_vendor_entry.vendor})"
                )
                continue

            mac_prefixes.add(mac_vendor_entry.mac_prefix)
            csv_writer.writerow(mac_vendor_entry.csv_line)

    print(f"Created {OUTPUT_FILE}", file=sys.stderr)


if __name__ == "__main__":
    main()
