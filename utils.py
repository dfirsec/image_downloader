__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.1.2"
__description__ = "Website Image Downloader"

import hashlib
import json
import logging
import re
import shutil
import sys
from functools import partial
from pathlib import Path
from urllib.parse import urljoin, urlparse

import cfscrape
import coloredlogs
import requests
from PIL import Image
from bs4 import BeautifulSoup
from colorama import init, Fore

# Initialize terminal colors
init()
gray = Fore.LIGHTBLACK_EX
green = Fore.GREEN
yellow = Fore.YELLOW
reset = Fore.RESET
magenta = Fore.MAGENTA

# Base directory path
parent = Path(__file__).resolve().parent


def dir_setup(url):
    """Sets up download directory."""
    url = "_dot_".join(urlparse(url).netloc.split(".")[1:])
    path = parent.joinpath(f"Image_Downloads/{url}")
    if not path.exists():
        path.mkdir(parents=True)
    return path


class FileHashing:
    """Return image file hash values."""

    def __init__(self, url):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")

    @staticmethod
    def get_hash(filepath, bs=65536):
        hasher = hashlib.sha256()
        with open(filepath, "rb") as file_obj:
            for chunk in iter(partial(file_obj.read, bs), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def file_hash(self, url):
        if not self.hashed_json.exists():
            with open(self.hashed_json, "w") as file_obj:
                file_obj.write(json.dumps({}))

        hashes = {}
        files = [f for f in Path(dir_setup(url)).iterdir() if f.is_file() and not f.name.endswith("json")]
        for _file in files:
            hashes.update({_file.name: self.get_hash(_file)})

        with open(self.hashed_json) as file_obj:
            data = json.load(file_obj)
        data.update(hashes)

        with open(self.hashed_json, "w") as file_obj:
            json.dump(data, file_obj, indent=4)


class Logging:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.propagate = False
        coloredlogs.install(level="DEBUG", fmt="%(asctime)s %(levelname)s %(message)s", logger=self.logger)


class Workers:
    """Content and link scraper."""

    def __init__(self, url, size, ext):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")
        self.url = url
        self.parser = urlparse(url)
        self.size = size
        self.ext = ext
        self.log = Logging().logger

        # keep track of small files not downloaded
        self.small_files = Path(dir_setup(url)).joinpath("small_image_files.log")

    def scraper(self, url):
        cloudflare_scraper = cfscrape.CloudflareScraper()
        resp = cloudflare_scraper.get(url, stream=True, timeout=10)
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
        except (requests.HTTPError, requests.ReadTimeout) as err:
            status = err.response.status_code
            if status in (403, 429):
                pass
            else:
                self.log.error(f"{str(err)}")
        except requests.exceptions.RequestException as err:
            self.log.error(f"{str(err)}")
        else:
            return resp

        return None

    def get_links(self, url):
        self.log.info(f"{'Gathering image links':>15}")
        try:
            resp = self.scraper(url)
            soup = BeautifulSoup(resp.content, "lxml")
        except AttributeError:
            sys.exit(self.log.error("Problem encountered accessing content"))
        else:
            # regex to validate urls
            regex_url = r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]" \
                        r"{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=\*]*))"

            # find all potential images sources
            img_src = ["data-src", "data-url", "src", "data-fallback-src", "data-srcset", "srcset"]
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
                sys.exit(self.log.info(f"{yellow}No images available for download{reset}"))
            else:
                return results

    def downloader(self, url, filename, size_results):
        session = requests.Session()
        resp = session.get(url, stream=True)
        try:
            resp.raise_for_status()
        except requests.exceptions.RequestException as error:
            sys.exit(self.log.error(f"{str(error)}"))
        else:
            with open(filename, "wb") as file_obj:
                resp.raw.decode_content = True
                shutil.copyfileobj(resp.raw, file_obj)
                self.log.info(f"{'Downloaded':>10} : {size_results}")
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

            # TODO: change image format to account for Cloudflare image compression
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
                size_results = f"{img_path.name} {gray}[{kb_size} kB]{reset}"

                # skip if image already exists in download directory
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
                    self.log.info(f"{resp.url} [{kb_size} kB]")
                    self.log.info(f"{magenta}{'Skipped':>10}{reset} : {size_results}")

                # pass to file downloader
                else:
                    self.downloader(url, img_path, size_results)
