import argparse
import hashlib
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from urllib.parse import urljoin, urlparse

import coloredlogs
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from termcolors import Termcolors

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.8"
__description__ = "Website Image Downloader"

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
    def __init__(self, url, size, ext):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")
        self.url = url
        self.parser = urlparse(url)
        self.size = size
        self.ext = ext

        # keep track of small files not downloaded
        self.small_files = parent.joinpath("small_image_files.txt")
        open(self.small_files, "w").close()  # create and close file

    @staticmethod
    def session_worker():
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504], raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def connector(self, url):
        session = self.session_worker()
        resp = session.get(url, timeout=10)
        resp.headers.update(
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            }
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            status = e.response.status_code
            errors = [403, 429]
            if status in errors:
                pass
            else:
                sys.exit(logger.error(f"{str(e)}"))
        except requests.exceptions.RequestException as e:
            sys.exit(logger.error(f"{str(e)}"))
        else:
            return resp

    def getlinks(self, url):
        logger.info(f"{'Gathering image links':>15}")
        resp = self.connector(url)
        try:
            soup = BeautifulSoup(resp.content, "lxml")
        except AttributeError:
            sys.exit(logger.error("Problem encountered accessing content"))
        else:
            # regex to validate urls
            regex_url = r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=\*]*))"

            # find all potential images sources
            img_src = ["data-src", "src", "data-fallback-src", "data-srcset", "srcset"]
            links1 = [link.get(src) for src in img_src for link in soup.find_all("img") if link.get(src) is not None]
            links2 = [i["href"] for i in (img.find_parent("a") for img in soup.select("a[href] img"))]
            links3 = [link.get("href") for link in soup.find_all("a")]
            matches = links1 + links2 + links3

            # validate the urls from combined full list
            links_joined = [urljoin(url, link) for link in matches]
            valid_url = [match.group(0) for match in re.finditer(regex_url, str(links_joined))]
            results = list(set(valid_url))  # remove any duplicates from list

            # if no images found
            if not results:
                sys.exit(logger.info(f"{tc.fg.yellow}No images available for download{tc.reset}"))
            else:
                return results

    def download(self, directory, url):
        resp = self.connector(url)
        img_path = Path(directory).joinpath(Path(url).name)
        try:
            # check for instance of headers
            bool(resp.headers)
        except Exception:
            pass
        else:
            # split content-type image/jpg, or image/gif, etc.
            img_maintype = resp.headers["Content-Type"].split("/")[0]
            img_subtype = resp.headers["Content-Type"].split("/")[1]

            if img_maintype == "image":
                content_len = len(resp.content)

                # convert content-length to kB size format
                kb_size = round(float(int(content_len) / 1000), 2)

                # remove special characters from string and add file extension if missing
                pattern = r"(\W(jpg|gif|png).*)"
                repl_str = re.sub(pattern, "", img_path.name)

                # replace file suffix with actaul image subtype
                suffix = img_path.suffix.replace(".", "")
                if suffix != img_subtype and img_subtype != "svg+xml" and suffix != "jpg":
                    img_path = Path(directory).joinpath(repl_str + "." + img_subtype)

                # image size results wrapper
                size_results = f"{img_path.name} {tc.fg.gray}[{kb_size} kB]{tc.reset}"

                if img_path.exists():
                    pass

                elif bool(self.ext) and self.ext == img_subtype:
                    pass

                elif content_len < self.size and not img_path.exists():
                    with open(self.small_files, "a") as f:
                        f.writelines(f"\nSmall File: {resp.url} [{kb_size} kB]")
                    logger.info(f"{tc.fg.magenta}{'Skipped':>10}{tc.reset} : {size_results}")

                else:
                    with open(img_path, "wb") as fileobj:
                        for chunk in resp.iter_content(chunk_size=1024):
                            if chunk:
                                fileobj.write(chunk)
                        logger.info(f"{'Downloaded':>10} : {size_results}")


def dir_setup(url):
    url = "_dot_".join(urlparse(url).netloc.split(".")[1:])
    path = parent.joinpath(f"IMG_Downloads/{url}")
    if not path.exists():
        path.mkdir(parents=True)
    return path


def main(url, size, ext=None, hashing=None):
    fh = FileHashing(url)
    download_dir = dir_setup(url)
    downloader = Downloader(url, size, ext)
    urls = [u for u in downloader.getlinks(url)]

    # Ref: https://docs.python.org/3/library/concurrent.futures.html
    max_threads = min(32, os.cpu_count() + 4) * 2  # double the default
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        download_func = partial(downloader.download, download_dir)
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

    # file size range (10kB - 50kB)
    def size_limit(arg):
        MIN = 10000
        MAX = 1000000
        try:
            f = int(float(arg) * 10 ** 3)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{tc.fg.yellow}Argument must be an integer value{tc.reset}")
        if f < MIN or f > MAX:
            raise argparse.ArgumentTypeError(
                f"{tc.fg.yellow}Value must be between {int(MIN/1000):} and {int(MAX/1000):} (kB){tc.reset}"
            )
        return f

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="destination url -- surround url string with double quotes")
    parser.add_argument(
        "-s",
        metavar="N",
        dest="size",
        type=size_limit,
        default=20000,
        help="size limit -- enter a value from 10 to 1000 (default value is 20, so anything less than 20kB will not be downloaded)",
    )
    parser.add_argument(
        "-e",
        dest="ext",
        metavar="",
        default=False,
        help="exclude image type/extension, i.e., exclude gif, jpg, webp, etc.",
    )
    parser.add_argument("-j", dest="hash", action="store_true", help="create json record of hashed image files")

    args = parser.parse_args()

    # remove dot from extension if present
    if args.ext:
        args.ext = args.ext.replace(".", "")

        # account for variation in jpg extension format
        if args.ext == "jpg" or args.ext == ".jpg":
            args.ext = "jpeg"

    logger.info(f"{'Initiating connection':>15}")
    main(args.url, args.size, args.ext, args.hash)
