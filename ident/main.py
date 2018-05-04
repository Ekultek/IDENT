from searcher import send_request
from lib.core import CoreEngine
from lib.formatter import (
   info,
   warn,
   prompt,
   debug
)
from lib.settings import (
    parse_settings,
    get_say_spec,
    get_string_log_level,
    generate_ip_ranges,
    write_to_file,
    CONF_FILE_PATH,
    BLACKLIST_CHECK_LINK,
    IP_DENIER_LOG_FILE_PATH
)


def main():
    ban_hammer = []
    statuses = []
    configured_settings = parse_settings(CONF_FILE_PATH)
    data_log_level = configured_settings["log_level"].split(":")[-1]
    verbose = True if data_log_level == "debug" else False
    if verbose:
        debug("setting log level to debug")
    network_range = generate_ip_ranges(
        configured_settings["network_ip_range"][0],
        configured_settings["network_ip_range"][1]
    )
    for item in configured_settings["filters"]:
        network_range.append(item)
    if verbose:
        write_to_file(network_range, IP_DENIER_LOG_FILE_PATH, "DEBUG")
    write_to_file("total of {} filters".format(len(network_range)), IP_DENIER_LOG_FILE_PATH)
    engine = CoreEngine(network_range, configured_settings["logfile"])
    found_matches = engine.pull_from_file()
    if verbose:
        debug("total matches {}".format(len(found_matches)))
        write_to_file(found_matches, IP_DENIER_LOG_FILE_PATH, "DEBUG")
    write_to_file("total of {} matches".format(len(found_matches)), IP_DENIER_LOG_FILE_PATH)
    intruders = engine.parse_matches(found_matches)
    total = len(intruders)
    if verbose:
        debug("intruder list: {}".format(intruders))
        write_to_file(intruders, IP_DENIER_LOG_FILE_PATH, "DEBUG")
    write_to_file("total of {} intruders", IP_DENIER_LOG_FILE_PATH)
    warn("found a total of {} possible intruders".format(total))
    say = True
    say_spec = get_say_spec(total)
    info("gathering a total of {} intruder IP address blacklist statuses".format(total))
    for i, ip in enumerate(intruders, start=1):
        if total - i < say_spec and say:
            info("almost done")
            say = False
        statuses.append(send_request(BLACKLIST_CHECK_LINK, ip))
    for status in statuses:
        _status = get_string_log_level(status[0], status[1], int(configured_settings["strict"]))
        if _status == 0:
            question = prompt(
                "this IP addresses blacklist count is at a medium interval, do you want to add it to the ban queue"
            )
            if question.lower().startswith("y"):
                ban_hammer.append(status[0])
        else:
            ban_hammer.append(status[0])
    if verbose:
        debug("all IP's in the deny queue: {}".format(ban_hammer))
        write_to_file(
            ban_hammer, IP_DENIER_LOG_FILE_PATH, "DEBUG"
        )
    write_to_file("total of {} in ddeny queue".format(len(ban_hammer)), IP_DENIER_LOG_FILE_PATH)
    warn("about to deny a total of {} IP addresses".format(len(ban_hammer)))
