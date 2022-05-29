"""
Python script parses tags that contain potential
links to image files and passes the results
to a downloader.
"""

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.1.3"
__description__ = "Website Image Downloader"

import argparse
import os
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from colorama import init, Fore

from utils import FileHashing, Workers, Logging, dir_setup

# Initialize terminal colors
init()
YELLOW = Fore.YELLOW
RESET = Fore.RESET


def main(url, size, ext=None, hashing=None):
    hasher = FileHashing(url)
    download_dir = dir_setup(url)
    worker = Workers(url, size, ext)

    urls = list(worker.get_links(url))

    # Ref: https://docs.python.org/3/library/concurrent.futures.html
    max_threads = min(32, os.cpu_count() + 4) * 2  # double the default
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        download_func = partial(worker.processor, download_dir)
        executor.map(download_func, urls, timeout=30)

    # Option to hash files
    if hashing:
        hasher.file_hash(url)


if __name__ == "__main__":
    banner = rf"""
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    | I m a g e   D o w n l o a d e r |
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    {__version__}         {__author__}
    """

    print(f"\033[36m{banner}\033[m")

    log = Logging().logger

    # file size range (10kB - 50kB)
    def size_limit(arg):
        _min = 10000
        _max = 1000000
        try:
            _float = int(float(arg) * 10**3)
        except ValueError as err:
            raise argparse.ArgumentTypeError(f"{YELLOW}Argument must be an integer value{RESET}") from err
        if _float < _min or _float > _max:
            raise argparse.ArgumentTypeError(
                f"{YELLOW}Value must be between {_min // 1000:} and {_max // 1000:} (kB){RESET}"
            )

        return _float

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="destination url -- surround url string with double quotes")
    parser.add_argument(
        "-s",
        metavar="size limit",
        dest="size",
        type=size_limit,
        default=20000,
        help="enter a value from 10 to 1000 (default = 20, less than 20kB will not be downloaded)",
    )
    parser.add_argument(
        "-e",
        dest="ext",
        metavar="exclude",
        default=False,
        help="exclude image type/extension, i.e., exclude gif, jpg, webp, etc.",
    )
    parser.add_argument("-j", dest="hash", action="store_true", help="create json record of hashed image files")

    args = parser.parse_args()

    # remove dot from extension if present
    if args.ext:
        args.ext = args.ext.replace(".", "")

        # account for variation in jpg extension format
        if args.ext in ("jpg", ".jpg"):
            args.ext = "jpeg"

    log.info(f"{'Initiating connection':>15}")
    main(args.url, args.size, args.ext, args.hash)
