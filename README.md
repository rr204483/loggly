# loggly
aggregates multiple file content in a chronological order

Loggly is small tool which aggregates multiple file content in a chronological order. Files can be in text, ak or gzip format.

This can act as a wrapper for aklog.
Inputs

(a) text file : Loggly expects files to be in : "<date>:<text>" format

(b) *.ak files

(c) *.gz files

(d) all unix patterns : *.*

(e) dirs
Filters

(a) search-pattern : text pattern to search for

(b) ignore-pattern : text pattern to ignore for

(c) from-date : select events that occurred after the specified date

(d) exact-date : select events that occurred on the specified date

(e) until-date : select events that occurred before the specified date
Output

(a) file : writes event data to a file on disk
Feautures

- sort & merge logs
- reads all ak timestamps
- search/ignore the strings
- date filters
- can be used in live machines
- takes all unix patterns
- clean rm log output
- recursive - act as a wrapper for aklog
- handling multi-line entry files
Usage

loggly [-h] [-n] [-k] [-p search-pattern] [-i ignore-pattern]
[-t from-date] [-e exact-date] [-T until-date] [-o filename]
file | directory [file | directory ...]

Aggregates multiple file content in a chronological order. Files can be in
text, ak or gzip format.
positional arguments:
file | directory

optional arguments:
-h, --help show this help message and exit
-n suppress filename
-k keep logs date format
-p search-pattern text pattern to search for
-i ignore-pattern text pattern to ignore for
-t from-date select events that occurred after the specified date
-e exact-date select events that occurred on the specified date
-T until-date select events that occurred before the specified date
-o filename output file

