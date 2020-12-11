#!/usr/bin/env python3
import sys
import os
import gzip
import collections

from typing import IO, Dict, Tuple, Any

def print_help():
    print(f"""{script_name} input_directory output_directory

This script adds fake agent hostnames and uuids to Zeek log records based on the IP addresses
contained in each record. The input directory should contain TSV Zeek logs which may be gzipped.
The output directory will contain the original logs with two new columns.
- agent_hostname
- agent_uuid

The values assigned to the two new fields depend on the configuration set inside this Python script.""")

############################ agent configuration ############################

# records with the following IPs will be assigned to their respective agents
# Alice has a office PC and a work from home device. Both have the same IP address, but
# they are connected to different networks.
alice_ip = "10.55.200.10"
# Before `alice_late_time` alice makes connections using her office PC.
alice_early_agent_hostname = "Alice Early"
alice_early_agent_uuid = "779a5281-949d-4ae3-9de4-309c955f48c0"
alice_late_time = 1517356800
# After `alice_late_time`, alice makes connections using her work from home device.
alice_late_agent_hostname = "Alice Late"
alice_late_agent_uuid = "439264be-a146-4759-80f7-f4fb23b9b346"

# Bob has a single IP on a single work from home device
bob_ip = "10.55.100.111"
bob_agent_hostname = "Bob"
bob_agent_uuid = "e59a5fc8-ebf5-4f82-b98e-ab2c7fad6099"

# All other IP addresses are to be understood as being on a different physical network.
# Carol is assigned all other IP addresses.
carol_agent_hostname = "Carol"
carol_agent_uuid = "5934e4c5-9acb-498f-a706-b4b7200a47aa"

def assign_agent(zfields: collections.OrderedDict) -> Tuple[str, str]:
    if zfields["id.orig_h"].value == alice_ip or zfields["id.resp_h"].value == alice_ip:
        if float(zfields["ts"].value) < alice_late_time:
            agent_hostname = alice_early_agent_hostname
            agent_uuid = alice_early_agent_uuid
        else:
            agent_hostname = alice_late_agent_hostname
            agent_uuid = alice_late_agent_uuid
    elif zfields["id.orig_h"].value == bob_ip or zfields["id.resp_h"].value == bob_ip:
        agent_hostname = bob_agent_hostname
        agent_uuid = bob_agent_uuid
    else:
        agent_hostname = carol_agent_hostname
        agent_uuid = carol_agent_uuid
    return agent_hostname, agent_uuid


###################### zeek file manipulation routines ######################

ZeekField = collections.namedtuple("ZeekField", ["name", "type", "value"])


class ZeekFileWriter:

    def __init__(self, file_path: str):
        self._name = file_path
        self._file = open(file_path, 'w')


    def __del__(self):
        self._file.close()


    def name(self) -> str:
        return self._name


    def write_header(self, header: collections.OrderedDict):
        separator = header['separator']
        del header['separator']
        self._file.writelines([
            "#separator " + separator.encode("unicode_escape").decode("utf-8") + "\n"
        ])

        lines = []
        for key, value in header.items():
            lines.append("#" + key + separator + value + "\n")
        self._file.writelines(lines)
        return


    def write_entry(self, fields: collections.OrderedDict, separator: str, set_separator: str):
        self._file.writelines([ZeekFileWriter.fmt_entry(fields, separator, set_separator)])


    @staticmethod
    def fmt_entry(fields: collections.OrderedDict, separator: str, set_separator: str) -> str:
        out_strings = []
        if "comment" in fields:
            out_strings.append("#" + fields["comment"].value)
        else:
            for field in fields.values():
                if isinstance(field.value, str):
                    out_strings.append(field.value)
                elif isinstance(field.value, collections.abc.Iterable):
                    out_strings.append(set_separator.join(field.value))
                else:
                    raise RuntimeError("Invalid data in ZeekField")
        out_strings.append("\n")
        return separator.join(out_strings)


class ZeekFileReader:

    def __init__(self, file_path: str):
        self._name = file_path
        if file_path.endswith(".gz"):
            self._file = gzip.open(file_path, 'r')
        else:
            self._file = open(file_path, 'r')
        self._header = ZeekFileReader.read_header(self._file)
        self._field_names = self._header["fields"].split(self.separator())
        self._field_types = self._header["types"].split(self.separator())


    def __del__(self):
        self._file.close()


    def __iter__(self):
        return self


    def __next__(self):
        prev_pos = self._file.tell()
        line = self._file.readline().strip().decode('utf-8')
        if self._file.tell() == prev_pos:
            raise StopIteration()
        return self.lex_line(line)


    def name(self) -> str:
        return self._name


    def header(self) -> collections.OrderedDict:
        return collections.OrderedDict(self._header)


    def obj_type(self) -> str:
        return self._header["path"]


    def separator(self) -> str:
        return self._header['separator']


    def set_separator(self) -> str:
        return self._header['set_separator']


    @staticmethod
    def read_header(fd: IO) -> collections.OrderedDict:
        header = collections.OrderedDict()

        # read separator
        fd.seek(0)
        l = fd.readline().strip()
        if not l.startswith(b"#separator"):
            raise RuntimeError(f"Cannot parse Zeek file (${fd.name}) with missing separator header.")
        header['separator'] = l.split(b" ")[1].decode('unicode_escape')

        # read header
        prev_l_pos = fd.tell()
        l = fd.readline().strip().decode('utf-8')
        while l.startswith("#"):
            l = l[1:]  # remove leading #
            sep_pos = l.index(header['separator'])

            key = l[:sep_pos]
            value = l[sep_pos+len(header['separator']):]
            header[key] = value

            prev_l_pos = fd.tell()
            l = fd.readline().strip().decode('utf-8')

        # rewind the file handle back a line
        fd.seek(prev_l_pos)

        return header


    def lex_line(self, line: str) -> collections.OrderedDict:
        fields = collections.OrderedDict()
        if line.startswith("#"):
            fields["comment"] = ZeekField("comment", "comment", line[1:])
            return fields

        tokens = line.split(self.separator())
        for i in range(len(tokens)):
            field_name = self._field_names[i]
            field_type = self._field_types[i]
            field_value = tokens[i]
            if field_type.startswith("set[") and field_type.endswith("]") or \
                field_type.startswith("vector[") and field_type.endswith("]"):
                field_value = field_value.split(self.set_separator())

            field = ZeekField(field_name, field_type, field_value)
            fields[field_name] = field
        return fields


############################# mapping routines #############################

def process_header(header: collections.OrderedDict):
    header["fields"] += header["separator"] + "agent_hostname"
    header["fields"] += header["separator"] + "agent_uuid"
    header["types"] += header["separator"] + "string"
    header["types"] += header["separator"] + "string"
    return header


def process_conn(conn: collections.OrderedDict):
    agent_hostname, agent_uuid = assign_agent(conn)
    conn["agent_hostname"] = ZeekField("agent_hostname", "string", agent_hostname)
    conn["agent_uuid"] = ZeekField("agent_uuid", "string", agent_uuid)
    return conn


def process_http(http: collections.OrderedDict):
    agent_hostname, agent_uuid = assign_agent(http)
    http["agent_hostname"] = ZeekField("agent_hostname", "string", agent_hostname)
    http["agent_uuid"] = ZeekField("agent_uuid", "string", agent_uuid)
    return http


def process_dns(dns: collections.OrderedDict):
    agent_hostname, agent_uuid = assign_agent(dns)
    dns["agent_hostname"] = ZeekField("agent_hostname", "string", agent_hostname)
    dns["agent_uuid"] = ZeekField("agent_uuid", "string", agent_uuid)
    return dns


def process_ssl(ssl: collections.OrderedDict):
    agent_hostname, agent_uuid = assign_agent(ssl)
    ssl["agent_hostname"] = ZeekField("agent_hostname", "string", agent_hostname)
    ssl["agent_uuid"] = ZeekField("agent_uuid", "string", agent_uuid)
    return ssl


def main(input_directory: str, output_directory: str):
    os.makedirs(output_directory, exist_ok=True)

    processor_map = {
        "http": process_http,
        "conn": process_conn,
        "dns": process_dns,
        "ssl": process_ssl,
    }

    file_names = [x for x in os.listdir(input_directory) if ".log" in x]

    for file_name in file_names:
        in_file = ZeekFileReader(os.path.join(input_directory, file_name))

        if in_file.obj_type() not in processor_map.keys():
            continue

        out_file = ZeekFileWriter(os.path.join(output_directory, file_name.replace(".gz", "")))

        print(f"Mapping {in_file.name()} to {out_file.name()}.", flush=True)

        out_header = process_header(in_file.header())
        out_file.write_header(out_header)

        i = 0
        for entry in in_file:
            if "comment" not in entry:
                entry = processor_map[in_file.obj_type()](entry)
            out_file.write_entry(entry, in_file.separator(), in_file.set_separator())
            i += 1
            if i % 10000 == 0:
                print(".", end="", flush=True)
        print("", flush=True)
    return


if __name__ == "__main__":
    try:
        script_name = sys.argv[0]
        input_directory = sys.argv[1]  # directory to read top level zeek files from (.log or .gz)
        output_directory = sys.argv[2]  # directory to write top level zeek files to after alterations
    except IndexError:
        print_help()
        exit(1)

    main(input_directory, output_directory)
