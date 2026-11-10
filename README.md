# csv-preflight

csv-preflight is a zero-dependency Python command line tool that checks a CSV file before you feed it to pandas, a database loader or a spreadsheet import. It reports the encoding, the delimiter it guessed and every structural problem that would otherwise make a parser fail halfway through the file instead of on line one: duplicate header names, blank header cells, rows with the wrong number of fields, blank records, NUL bytes, mixed line endings and non-UTF-8 encodings.

The output is line-numbered, and the exit code is meant for CI, so a broken export fails the pipeline instead of silently becoming an empty dataframe downstream.

## Why

Most CSV failures are cheap to detect and expensive to debug: a file saved as UTF-16 opens as one giant column, a semicolon export looks like a single column of text, and one unquoted comma on row 40000 shifts every field after it. csv-preflight reads the whole file once, front to back, and says exactly where the damage starts.

## Requirements

Python 3.8 or newer. No third-party packages.

## Install

```bash
git clone https://github.com/wyn-cmd/csv-preflight.git
cd csv-preflight
chmod +x csv_preflight.py
```

Optionally put it on your PATH:

```bash
mkdir -p ~/.local/bin
cp csv_preflight.py ~/.local/bin/csv-preflight
```

## Usage

```bash
python3 csv_preflight.py data/orders.csv
```

```
data/orders.csv: utf-8, delimiter ',', 4 columns, 1200 data rows
  error   CF004 line 418: row has 5 fields, header has 4
  warning CF003 line 1: column 3 header has surrounding whitespace: ' total'
```

Machine readable output for a pipeline:

```bash
python3 csv_preflight.py data/orders.csv --format json --quiet
echo $?    # 0 clean, 2 findings, 1 the tool could not read the file
```

Check several files at once:

```bash
python3 csv_preflight.py exports/*.csv --format json
```

Override the guess when you already know the dialect, and raise the size cap for a big export:

```bash
python3 csv_preflight.py survey.csv --delimiter ';' --max-bytes 268435456
```

## Findings

| Code | Severity | Meaning |
| --- | --- | --- |
| CF001 | error | Two header cells name the same column, ignoring case |
| CF002 | error | A header cell is empty |
| CF003 | warning | A header cell has leading or trailing whitespace |
| CF004 | error | A data row has more or fewer fields than the header |
| CF005 | warning | A blank record, usually a doubled newline |
| CF006 | error | NUL bytes present, so the file is not plain text |
| CF007 | warning | More than one line ending convention in the same file |
| CF008 | warning | Encoding is not UTF-8, so strict readers will fail |
| CF009 | warning | Header is a single column, so the delimiter guess is probably wrong |
| CF010 | warning | Two candidate delimiters scored the same, so pass `--delimiter` |

Errors set the exit code to 2. Warnings are printed but still exit 0. Files above `--max-bytes` (64 MiB by default) are refused rather than read into memory.

## How it works

The file is read as raw bytes first, because the encoding has to be settled before any parsing can be trusted: a BOM is checked for UTF-32, UTF-8 and UTF-16, then the bytes are validated as UTF-8, then cp1252 and latin-1 are tried as fallbacks. Delimiter detection counts candidate delimiters outside quotes across the first hundred lines and picks the one whose per-line count is most consistent. Records are then split with `csv.reader` while a quote-parity check keeps track of the physical line each record starts on, so a message about row 40 points at line 40 even when earlier fields contained embedded newlines.

## Tests

```bash
python3 -m unittest -v test_csv_preflight
```

25 tests cover BOM precedence, fallback decoding, delimiter scoring, every finding code, multiline quoted fields, the size cap and the CLI exit codes.

## Limitations

The delimiter guess is a heuristic and can be beaten by a file whose text contains many semicolons inside one unwrapped column; pass `--delimiter` when you know the dialect. Encoding detection has no chardet fallback, so a legacy codepage that is not cp1252 or latin-1 will decode as mojibake with only the CF008 warning. Field-level type checking is out of scope: this tool checks structure, not values.

## License

MIT. See LICENSE.
