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
from pathlib import Path
from urllib.parse import urljoin, urlparse

import cfscrape
import coloredlogs
import requests
from bs4 import BeautifulSoup
from PIL import Image

from termcolors import Termcolors

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.1.1"
__description__ = "Website Image Downloader"

logger = logging.getLogger(__name__)
logger.propagate = False
coloredlogs.install(level="DEBUG", fmt="%(asctime)s %(levelname)s %(message)s", logger=logger)

# Initialize terminal colors
tc = Termcolors()

# Base directory path
parent = Path(__file__).resolve().parent


class FileHashing:
    def __init__(self, url):
        """Return image file hash values."""
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")

    @staticmethod
    def gethash(filepath, blocksize=65536):
        hasher = hashlib.sha256()
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
        for f in files:
            hashes.update({f.name: self.gethash(f)})

        with open(self.hashed_json) as f:
            data = json.load(f)
        data.update(hashes)

        with open(self.hashed_json, "w") as f:
            json.dump(data, f, indent=4)


class Worker:
    def __init__(self, url, size, ext):
        """Returns content and link scraper."""
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")
        self.url = url
        self.parser = urlparse(url)
        self.size = size
        self.ext = ext

        # keep track of small files not downloaded
        self.small_files = Path(dir_setup(url)).joinpath("small_image_files.log")

    @staticmethod
    def scraper(url):
        cfscraper = cfscrape.CloudflareScraper()
        resp = cfscraper.get(url, stream=True, timeout=10)
        resp.headers.update(
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "max-age=0",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/89.0",
            }
        )
        try:
            resp.raise_for_status()
        except (requests.HTTPError, requests.ReadTimeout) as e:
            status = e.response.status_code
            if status in (403, 429):
                pass
            else:
                logger.error(f"{str(e)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"{str(e)}")
        else:
            return resp

    def getlinks(self, url):
        logger.info(f"{'Gathering image links':>15}")
        try:
            resp = self.scraper(url)
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
            links3 = [link.get("href") for link in soup.find_all("a") if link.get("href") is not None]
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

    @staticmethod
    def downloader(url, filename, size_results):
        session = requests.Session()
        resp = session.get(url, stream=True)
        try:
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            sys.exit(logger.error(f"{str(e)}"))
        else:
            with open(filename, "wb") as f:
                resp.raw.decode_content = True
                shutil.copyfileobj(resp.raw, f)
                logger.info(f"{'Downloaded':>10} : {size_results}")
            return filename

    def processor(self, directory, url):
        resp = self.scraper(url)
        img_path = Path(directory).joinpath(Path(url).name)
        try:
            bool(resp.headers)  # check for instance of headers
        except requests.exceptions.RequestException:
            pass
        else:
            # image file formats
            img_format = ("apng", "bmp", "gif", "jpeg", "png", "webp")

            # TODO: change image format to account for cloudlfare image compression
            # https://support.cloudflare.com/hc/en-us/articles/360000607372-Using-Cloudflare-Polish-to-compress-images
            # if "jpeg" in resp.headers["Cf-Polished"]:
            #     img_subtype = "jpeg"

            img_subtype = Image.open(resp.raw).format.lower()

            if img_subtype in img_format:
                content_len = resp.headers["Content-length"]

                # convert content-length to kB size format
                kb_size = round(float(int(content_len) / 1000), 2)

                # remove special characters from string and add file extension if missing
                pattern = r"(\W(jpg|gif|png).*)"
                repl_str = re.sub(pattern, "", img_path.name)

                # replace file suffix with actual image subtype
                suffix = img_path.suffix.replace(".", "")
                if suffix != img_subtype:
                    img_path = Path(directory).joinpath(repl_str + "." + img_subtype)

                # image size results wrapper
                size_results = f"{img_path.name} {tc.fg.gray}[{kb_size} kB]{tc.reset}"

                # skip if image already existsin download directory
                if img_path.exists():
                    pass

                # check if image file format argument is passed
                elif bool(self.ext) and self.ext == img_subtype:
                    pass

                # skip image file by size and write to log
                elif int(content_len) < self.size:
                    logging.basicConfig(
                        format="%(message)s",
                        filename=self.small_files,
                        filemode="w",
                        level=logging.INFO,
                    )
                    logging.info(f"{resp.url} [{kb_size} kB]")
                    logger.info(f"{tc.fg.magenta}{'Skipped':>10}{tc.reset} : {size_results}")

                # pass to file downloader
                else:
                    self.downloader(url, img_path, size_results)


def dir_setup(url):
    """Sets up download directory."""
    url = "_dot_".join(urlparse(url).netloc.split(".")[1:])
    path = parent.joinpath(f"Image_Downloads/{url}")
    if not path.exists():
        path.mkdir(parents=True)
    return path


def main(url, size, ext=None, hashing=None):
    fh = FileHashing(url)
    download_dir = dir_setup(url)
    worker = Worker(url, size, ext)
    urls = list(worker.getlinks(url))

    # Ref: https://docs.python.org/3/library/concurrent.futures.html
    max_threads = min(32, os.cpu_count() + 4) * 2  # double the default
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        download_func = partial(worker.processor, download_dir)
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
        help="size limit -- enter a value from 10 to 1000 (default = 20, less than 20kB will not be downloaded)",
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
        if args.ext in ("jpg", ".jpg"):
            args.ext = "jpeg"

    logger.info(f"{'Initiating connection':>15}")
    main(args.url, args.size, args.ext, args.hash)
