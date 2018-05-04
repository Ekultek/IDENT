import re
import os
import time
import shlex
import datetime
import subprocess
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from lib.formatter import (
    info,
    error,
    fatal
)


CONF_FILE_PATH = "{}/IDENT.conf".format(os.getcwd())
IP_DENIER_LOG_FILE_PATH = "{}/.ip_denier_log/{}-ident-log.log".format(
    os.path.expanduser("~"), datetime.datetime.today().strftime("%Y%m%d")
)
IP_FINDER = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
BLACKLIST_CHECK_LINK = "http://www.ipvoid.com/ip-blacklist-check/"


def parse_settings(conf_file_path):
    opts = {}
    parser = ConfigParser.ConfigParser(allow_no_value=True)
    parser.read(conf_file_path)
    sections = parser.sections()
    for section in sections:
        for opt in parser.options(section):
            opts[opt] = parser.get(section, opt)
    try:
        opts["filters"] = opts["filters"].split(",")
        opts["network_ip_range"] = opts["network_ip_range"].split(",")
    except:
        opts["filters"] = list(opts["filters"])
        opts["network_ip_range"] = list(opts["network_ip_range"])
    return opts


def write_to_file(data, logfile_path, level="INFO"):
    directory_to_check = logfile_path.split("/")
    directory_to_check.pop()
    directory_to_check = '/'.join(directory_to_check)
    if not os.path.exists(directory_to_check):
        os.mkdir(directory_to_check)
    with open(logfile_path, "a+") as log:
        log.write("[{} {}] {}{}".format(
            time.strftime("%H:%M:%S"), level,
            data, os.linesep
        ))
    return logfile_path


def generate_ip_ranges(start_ip, end_ip):
    import socket
    import struct

    start_node = struct.unpack('>I', socket.inet_aton(start_ip))[0]
    end_node = struct.unpack('>I', socket.inet_aton(end_ip))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start_node, end_node)]


def get_say_spec(total):
    if total >= 100:
        say_spec = 30
    elif total <= 100 >= 50 <= 30:
        say_spec = 15
    else:
        say_spec = 5
    return say_spec


def get_string_log_level(ip, spec, strict):
    blacklists = int(spec.split("/")[0].split(" ")[-1])
    total_lists = spec.split("/")[-1]
    output_string = "{} is blacklisted on {} out of {} lists".format(ip, blacklists, total_lists)
    if strict == 1:
        fatal(output_string) if blacklists != 0 else info(output_string)
        return 1
    if blacklists <= strict:
        info(output_string)
        return -1
    elif strict <= blacklists <= 4:
        error(output_string)
        return 0
    else:
        fatal(output_string)
        return 1


def send_command(command, ip_address_to_block, sep="-" * 30):
    command = command.format(ip_address_to_block)
    command_list = shlex.split(command)
    write_to_file("calling command", IP_DENIER_LOG_FILE_PATH)
    print(sep)
    with subprocess.Popen(command_list) as proc:
        print(proc.stdout.read())
    print(sep)


