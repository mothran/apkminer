# apkminer

Simple program to mine through APKs at high speed.  It uses a modular method of calling specific analyzers on each apk provided

## Setup

```bash
git submodule init
git submodule update
```

Standard CPython works fine but I highly recommend pypy, I have seen 70% faster runs using pypy.

## Usage

```
usage: apkminer.py [-h] [-i IN_DIR] [-o LOG_FILE] [-c CORES] [-a ANALYZER]
                   [-l]

analyzer of APKs

optional arguments:
  -h, --help            show this help message and exit
  -i IN_DIR, --in_dir IN_DIR
                        directory of apk files to analyze
  -o LOG_FILE, --log_file LOG_FILE
                        log file to write to
  -c CORES, --cores CORES
                        force a number of cores to use
  -a ANALYZER, --analyzer ANALYZER
                        Select the analyzer you want to use.
  -l, --list_analyzers  List the possible analyzers
```

## Analyzers

```
private_keys  -  Find private keys in files or dex strings
elf_files     -  Report string data from specific sections of elf files
aws_finder    -  Find AWS key pairs in files and dex strings
so_census     -  Report on data about .so's in APKs
silverpush    -  Finds apks that contain the silverpush library
```

## Dependencies

- pyelftools

