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


## Writing an analyzer

Below I will layout the steps for writing an analyzer and the components of apkminer that a analyzer developer should understand.

### Analyzer template

```python
# import the utils.py file for helper functions and Logger object
from utils import *

# Define the analyzer() function, this function name needs to be the same for each analyzer
# because apkminer searches for this function name.
def analyze(args, apk_queue, res_queue, output_data):
	# The Logger class uses a multiprocessing Queue to perform atomic writes to the defined log file
	# this is helpful for debugging data and logging and errors that might occur during the run.
	log = Logger(args.log_file, res_queue)

	# Continually check the input 'apk_queue' for new file names
	while True:
		# break the loop if the queue is empty
		if apk_queue.empty():
			return
		else:
			# fetch the file off the queue
			apk_file = apk_queue.get()

			# Logging works similar to stdout / stderr,
			# the log() function writes to an internal buffer (new line delimited)
			# then flush() pushes the data the actually logging process
			log.log(apk_file)
			log.flush()

			# write analyzer here.
```

In order to register a analyzer inside of apkminer, save the analyzer as a .py in the analyzers/ directory and then edit analyzers/__init__.py to include the name of your analyzer.

For example:

```
analyzers/test_analyzer.py
```

Then add "test_analyzer" to the line import list in __init__.py

Check out the aws_finder.py or other analyzers for examples.  Also spend some time looking at the helper functions inside of utils.py.

### Optional features for analyzers

In order to enable structured output that is separate from the log file a analyzer writer can define two other methods in their .py file:

1. output_results - Used for bulk writes after completion of all input apk's.
2. stream_results - Used for streaming results as they are generated.

### output_results example

```python
import pickle

def output_results(output_data):
	fd = open("output.pick", "wb")
	pickle.dump(output_data, fd)
	fd.close()
```

### stream_results example

```python
import csv
import Queue

def stream_results(output_queue, end_event):
	csv_fd = open('test.csv', 'wb')
	datawriter = csv.writer(csv_fd)

	while not end_event.is_set():
		try:
			data = output_queue.get(True, 1)
			datawriter.writerow(data)

		except Queue.Empty:
			continue
```
