# Image Downloader

![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

I created this script as a method to download image files from forums that I visit. A few tests have demostrated that the script is generally successful across other "basic" websites, however, website coding complexity may pose issues extracting image links.

Basically, the script parses tags that contain potential links to image files and passes the results to a downloader. The script is a bit crude, but expect updates to optimize code.

**Files created by script:**

- Image files container for:
  - Downloaded image files
  - JSON file of hashed image files
- Log record of small images files skipped

## Installation

```text
git clone https://github.com/dfirsec/image_downloader.git
cd image_downloader
pip install -r requirements.txt
```

## Usage

```text
usage: image_downloader.py [-h] [-s N] [-e] [-j] url

positional arguments:
  url         destination url -- surround url string with double quotes

optional arguments:
  -h, --help  show this help message and exit
  -s N        size limit -- enter a value from 10 to 50 (default value is 20, so anything less than 20kB will not be downloaded)
  -e          exclude image type/extension, i.e., exclude gif, jpg, webp, etc.
  -j          create json record of hashed image files
```

### Example Run

```text
python image_downloader.py "<URL>"

    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    | I m a g e   D o w n l o a d e r |
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    v0.x.x         DFIRSec (@pulsecode)

2021-03-09 08:26:28 INFO Connecting to: https://<URL>
2021-03-09 08:26:28 INFO Downloaded: 20190327_174324.jpg
2021-03-09 08:26:28 INFO Downloaded: 20200309_212330.jpg
2021-03-09 08:26:29 INFO Downloaded: 20180830_161521.jpg
2021-03-09 08:26:29 INFO Downloaded: 20190714_1636310.jpg
2021-03-09 08:26:30 INFO Downloaded: 20180910_120057.jpg
2021-03-09 08:26:30 INFO Downloaded: 20190714_163640.jpg
2021-03-09 08:26:30 INFO Downloaded: 20190327_131047.jpg
```

#### Option to skip image files smaller that 20kB. Default is 20, or specify between 10 - 50

```text
python image_downloader.py "<URL>" -s

    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    | I m a g e   D o w n l o a d e r |
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+-+
    v0.0.1         DFIRSec (@pulsecode)

2021-03-09 08:53:12 INFO File Exists: 20200312_170237.jpg
2021-03-09 08:53:12 INFO File Exists: 20190326_170715.jpg
2021-03-09 08:53:12 INFO Small Image: 1235699.svg [3.58 kB]
2021-03-09 08:53:12 INFO Small Image: abcdefg.png [9.05 kB]
2021-03-09 08:53:12 INFO Small Image: xyz.png [3.75 kB]
2021-03-09 08:53:12 INFO File Exists: 20190714_163629.jpg
2021-03-09 08:53:12 INFO File Exists: 20200309_170653.jpg
```

```text
<<< small_image_files.txt >>>
Small File: <URL>/1235699.svg [3.75 KB]
Small File: <URL>/abcdefg.png [3.985 KB]
Small File: <URL>/xyz.png [5.091 KB]
```

#### Option to skip certain image file extensions, i.e., gif, jpg, png, webp

```text
python image_downloader.py "<URL>" -e <EXTENSION>
```

#### Option to create json record of hashed image files

```text
python image_downloader.py "<URL>" -j
```
