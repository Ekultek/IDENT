import argparse


class IdentParser(argparse.ArgumentParser):

    def __int__(self):
        super(argparse.ArgumentParser).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser()
        optional = parser.add_argument_group()
        optional.add_argument(
            "-t", "--text", action="store_true", dest="sendToTextFile",
            help="create a text file that will contain all `bad` IP addresses "
                 "one per line"
        )
        optional.add_argument(
            "-c", "--csv", action="store_true", dest="sendToCsvFile",
            help="create a CSV file that will contain all `bad` IP addresses "
                 "it will be in the format ip,amount-of-lists,total-lists"
        )
        optional.add_argument(
            "-v", "--verbose", action="store_true", dest="verbose",
            help="run in verbose mode and log with verbosity"
        )
        return parser.parse_args()