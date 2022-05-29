import hashlib
import json
import logging
import re
import shutil
import sys
from functools import partial
from pathlib import Path
from typing import List
from urllib.parse import urljoin, urlparse

import cfscrape
import coloredlogs
import requests
from bs4 import BeautifulSoup
from colorama import Fore, init
from PIL import Image

# Initialize terminal colors
init()
GRAY = Fore.LIGHTBLACK_EX
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Fore.RESET
MAGENTA = Fore.MAGENTA

# Base directory path
parent = Path(__file__).resolve().parent


def dir_setup(url):
    """Sets up download directory."""
    url = "_dot_".join(urlparse(url).netloc.split(".")[1:])
    path = parent.joinpath(f"Image_Downloads/{url}")
    if not path.exists():
        path.mkdir(parents=True)
    return path


# It takes a URL, creates a directory, and hashes all the files in that directory
class FileHashing:
    """Return image file hash values."""

    def __init__(self, url):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")

    @staticmethod
    def get_hash(filepath, blocksize=65536):
        """
        It reads the file in chunks of 65536 bytes, and updates the hash with each chunk.

        :param filepath: The path to the file you want to hash
        :param blocksize: The size of the block to read from the file, defaults to 65536 (optional)
        :return: The hash of the file.
        """
        hasher = hashlib.sha256()
        with open(filepath, "rb") as fileobj:
            for chunk in iter(partial(fileobj.read, blocksize), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def file_hash(self, url):
        """
        It takes a url, checks if a json file exists, if not it creates one, then it creates a list of
        files in the directory, then it creates a dictionary of the file names and hashes, then it opens
        the json file, loads the data, updates the data with the new dictionary, then it writes the data
        to the json file.

        :param url: The URL of the website you want to download
        """
        if not self.hashed_json.exists():
            with open(self.hashed_json, "w", encoding="utf-8") as fileobj:
                fileobj.write(json.dumps({}))

        files = [f for f in Path(dir_setup(url)).iterdir() if f.is_file() and not f.name.endswith("json")]
        hashes = {_file.name: self.get_hash(_file) for _file in files}
        with open(self.hashed_json, encoding="utf-8") as file_obj:
            data = json.load(file_obj)
        data.update(hashes)

        with open(self.hashed_json, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, indent=4)


class Logging:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.propagate = False
        coloredlogs.install(level="DEBUG", fmt="%(asctime)s %(levelname)s %(message)s", logger=self.logger)


class Workers:
    """Content and link scraper."""

    def __init__(self, url: str, size: int, ext: str):
        self.hashed_json = Path(dir_setup(url)).joinpath("hashed_files.json")
        self.url = url
        self.parser = urlparse(url)
        self.size = size
        self.ext = ext
        self.log = Logging().logger

        # keep track of small files not downloaded
        self.small_files = Path(dir_setup(url)).joinpath("small_image_files.log")

    def scraper(self, url: str):
        """
        It takes a URL, makes a request to it, and returns the response

        :param url: str = "hxxps://URL"
        :type url: str
        :return: A response object.
        """
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
            if status not in (403, 429):
                self.log.error(f"{str(err)}")
        except requests.exceptions.RequestException as err:
            self.log.error(f"{str(err)}")
        else:
            return resp

        return None

    def get_links(self, url: str) -> List:
        """
        It takes a url, scrapes the page for image links, validates the links, and returns a list of
        valid links

        :param url: str = "hxxps://URL"
        :type url: str
        :return: A list of urls
        """
        self.log.info(f"{'Gathering image links':>15}")
        try:
            resp = self.scraper(url)
            soup = BeautifulSoup(resp.content, "lxml")
        except AttributeError:
            sys.exit(self.log.error("Problem encountered accessing content"))
        else:
            # regex to validate urls
            regex_url = (
                r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]"
                r"{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=\*]*))"
            )

            # find all potential images sources
            img_src = ["data-src", "data-url", "src", "data-fallback-src", "data-srcset", "srcset"]
            links1 = [link.get(src) for src in img_src for link in soup.find_all("img") if link.get(src) is not None]
            links2 = [i["href"] for i in (img.find_parent("a") for img in soup.select("a[href] img"))]
            links3 = [link.get("href") for link in soup.find_all("a") if link.get("href") is not None]
            matches = links1 + links2 + links3

            # validate the urls from combined full list
            links_joined = [urljoin(url, link) for link in matches]
            valid_url = [match.group(0) for match in re.finditer(regex_url, str(links_joined))]
            if results := list(set(valid_url)):
                return results
            sys.exit(self.log.info(f"{YELLOW}No images available for download{RESET}"))

    def downloader(self, url: str, filename: Path, size_results: str):
        """
        It downloads a file from a URL, and writes it to a file on disk

        :param url: str = The URL of the file to download
        :type url: str
        :param filename: The name of the file to be downloaded
        :type filename: Path
        :param size_results: str = "1.2 MB"
        :type size_results: str
        :return: The filename is being returned.
        """
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

    def processor(self, directory: Path, url: str) -> None:
        """
        It checks if the image file format is in the list of image file formats, then it checks if the
        image file format argument is passed, then it checks if the image file size is less than the
        image file size argument, then it passes the image file to the file downloader.

        :param directory: Path
        :type directory: Path
        :param url: The URL of the image to download
        :type url: str
        """
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
                    img_path = Path(directory).joinpath(f"{repl_str}.{img_subtype}")

                # image size results wrapper
                size_results = f"{img_path.name} {GRAY}[{kb_size} kB]{RESET}"

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
                    self.log.info(f"{MAGENTA}{'Skipped':>10}{RESET} : {size_results}")

                # pass to file downloader
                else:
                    self.downloader(url, img_path, size_results)
