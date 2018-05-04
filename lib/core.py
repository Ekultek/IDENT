from lib.settings import IP_FINDER


class CoreEngine(object):

    def __init__(self, filters, file_path):
        self.filters = filters
        self.file_path = file_path

    def pull_from_file(self):
        found = []
        flatten = lambda l: [item for sublist in l for item in sublist]
        with open(self.file_path, "rb") as data:
            for line in data.readlines():
                found_ip = IP_FINDER.findall(line)
                found.append(found_ip)
        return flatten(found)

    def parse_matches(self, found):
        retval = set()
        for item in found:
            if item not in self.filters:
                retval.add(item)
        return retval
