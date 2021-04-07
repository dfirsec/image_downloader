import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http.client import responses
from pathlib import Path
from urllib.parse import urljoin, urlparse

import coloredlogs
import requests
from bs4 import BeautifulSoup

from termcolors import Termcolors

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.4"
__description__ = "Website image downloader"

logger = logging.getLogger(__name__)
coloredlogs.install(level="DEBUG", fmt="%(asctime)s %(levelname)s %(message)s", logger=logger)

# Initialize terminal colors
tc = Termcolors()

# Base directory path
parent = Path(__file__).resolve().parent


class FileHashing:
    def __init__(self, url):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")

    @staticmethod
    def gethash(filepath, blocksize=65536):
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(partial(f.read, blocksize), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def hashfiles(self, url):
        if not self.hashed_json.exists():
            with open(self.hashed_json, "w") as f:
                f.write(json.dumps({}))

        hashes = {}
        files = [f for f in Path(dir_setup(url)).iterdir() if f.is_file() and not f.name.endswith("json")]
        [hashes.update({f.name: self.gethash(f)}) for f in files]

        with open(self.hashed_json) as f:
            data = json.load(f)
        data.update(hashes)

        with open(self.hashed_json, "w") as f:
            json.dump(data, f, indent=4)


class Downloader:
    def __init__(self, url, skip):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36"
        }
        self.url = url
        self.resp = requests.get(url, headers=self.headers)
        self.parser = urlparse(url)
        self.skip = skip
        # keep track of small files not downloaded
        self.small_files = parent.joinpath("small_image_files.txt")
        open(self.small_files, "w").close()  # create and close file

    def getlinks(self, url):
        try:
            logger.info(f"{'Connecting to':>15} : {tc.fg.cyan}{url}{tc.reset}")
            soup = BeautifulSoup(self.resp.content, "lxml")
            self.resp.raise_for_status()
        except Exception as err:
            logger.error(f"{self.resp.status_code} {responses[self.resp.status_code]}: {url}")
            sys.exit(logger.error(err))
        else:
            # regex to validate urls
            regex_url = r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=\*]*))"

            # find all potential images sources
            img_src = ["data-src", "src", "data-fallback-src", "data-srcset", "srcset"]
            img_links1 = [link.get(src) for src in img_src for link in soup.find_all("img") if link.get(src) != None]
            img_links2 = [i["href"] for i in (img.find_parent("a") for img in soup.select("a[href] img"))]
            img_links3 = [link.get("href") for link in soup.find_all("a")]
            matches = img_links1 + img_links2 + img_links3

            # validate the urls from combined full list
            links_joined = [urljoin(url, link) for link in matches]
            valid_url = [match.group(0) for match in re.finditer(regex_url, str(links_joined))]
            results = list(set(valid_url))  # remove any duplicates from list

            # if no images found
            if not results:
                sys.exit(logger.info(f"{tc.fg.yellow}No images available for download{tc.reset}"))
            else:
                return results

    def download_file(self, directory, url):
        resp = requests.get(url, headers=self.headers, stream=True)
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                pass
            else:
                logger.error(f"{'Error':>15} : {str(e)}: {url}")
        except Exception as e:
            logger.error(f"{'Error':>15} : {str(e)}: {url}")
        else:
            img_path = Path(directory).joinpath(Path(url).name)
            img_size = int(resp.headers["Content-Length"], 0)
            file_size = round(float(int(img_size) / 1000), 2)

            img_maintype = resp.headers["Content-Type"].split("/")[0]
            img_subtype = resp.headers["Content-Type"].split("/")[1]

            if img_maintype == "image":
                # remove special characters from string and add file extension if missing
                pattern = r"(\W(jpg|gif|png).*)"
                repl_str = re.sub(pattern, "", img_path.name)

                # replace file suffix with image subtype
                suffix = img_path.suffix.replace(".", "")
                if suffix != img_subtype and img_subtype != "svg+xml" and suffix != "jpg":
                    img_path = Path(directory).joinpath(repl_str + "." + img_subtype)

                if bool(img_size < self.skip) and not img_path.exists():
                    with open(self.small_files, "a") as f:
                        f.writelines(f"\nSmall File: {resp.url} [{file_size} KB]")
                    logger.info(
                        f"{tc.fg.magenta}{'Skipping Image':>15}{tc.reset} : {img_path.name} {tc.fg.gray}({file_size} kB){tc.reset}"
                    )

                elif img_path.exists():
                    logger.info(
                        f"{tc.fg.yellow}{'File Exists':>15}{tc.reset} : {img_path.name} {tc.fg.gray}({file_size} kB){tc.reset}"
                    )

                else:
                    with open(img_path, "wb") as fileobj:
                        resp.raw.decode_content = True
                        shutil.copyfileobj(resp.raw, fileobj)
                        logger.info(f"{'Downloaded':>15} : {img_path.name}")


def dir_setup(url):
    url = ".".join(urlparse(url).netloc.split(".")[1:])
    path = parent.joinpath(f"IMG_Downloads/{url}")
    if not path.exists():
        path.mkdir(parents=True)
    return path


def main(url, skip, hashing=None, max_threads=None):
    fh = FileHashing(url)
    downloader = Downloader(url, skip)
    download_dir = dir_setup(url)
    urls = [u for u in downloader.getlinks(url)]

    # If max_workers is None, it will default to min(32, os.cpu_count() + 4)
    # Ref: https://docs.python.org/3/library/concurrent.futures.html
    if max_threads:
        max_threads = min(32, os.cpu_count() + 4) * 2  # double the default
    else:
        max_threads = None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        download_func = partial(downloader.download_file, download_dir)
        executor.map(download_func, urls, timeout=30)

    # Option to hash files
    if hashing:
        fh.hashfiles(url)


if __name__ == "__main__":
    banner = fr"""
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    | I m a g e   D o w n l o a d e r |
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    {__version__}         {__author__}
    """

    print(f"\033[36m{banner}\033[m")

    # size range for file size (10kB - 50kB)
    def size_limit(arg):
        MIN = 10000
        MAX = 50000
        try:
            f = int(float(arg) * 10 ** 3)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{tc.fg.yellow}Argument must be an integer value{tc.reset}")
        if f < MIN or f > MAX:
            raise argparse.ArgumentTypeError(f"{tc.fg.yellow}Argument must be > {MIN:,} kB and < {MAX:,} kB{tc.reset}")
        return f

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="destination url -- surround url string with double quotes")
    parser.add_argument(
        "-s",
        metavar="N",
        dest="skip",
        type=size_limit,
        default=20000,
        help="skip image files < 20kB, or specify size from 10 to 50",
    )
    parser.add_argument("-m", dest="max", action="store_true", help="use max threads for downloading")
    parser.add_argument("-j", dest="hash", action="store_true", help="create json record of hashed image files")

    args = parser.parse_args()

    main(args.url, args.skip, args.hash, args.max)
