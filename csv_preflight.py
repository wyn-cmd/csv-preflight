# csv-preflight: check a CSV file before anything parses it
# Reports the encoding, the delimiter, and the structural problems that make a
# parser fail halfway through a file instead of on line one.
#
# Standard library only. Python 3.8 and newer.

import argparse
import codecs
import csv
import io
import json
import os
import sys

# BOM signatures, longest first so UTF-32 is not mistaken for UTF-16
BOM_TABLE = [
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
]

# Delimiters worth trying when nothing is declared
CANDIDATE_DELIMITERS = [",", ";", "\t", "|"]

# Severity levels used in findings
ERROR = "error"
WARNING = "warning"

# Default cap so an accidental multi-gigabyte target does not eat memory
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


# Read the raw bytes of a file, refusing anything above the size cap
def read_bytes(path, max_bytes=DEFAULT_MAX_BYTES):
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError(
            "%s is %d bytes, above the %d byte cap; pass --max-bytes to raise it"
            % (path, size, max_bytes)
        )
    with open(path, "rb") as handle:
        return handle.read()


# Work out the encoding from a BOM, then from strict UTF-8, then fall back
def detect_encoding(raw):
    for bom, label in BOM_TABLE:
        if raw.startswith(bom):
            return label, "bom"
    try:
        raw.decode("utf-8")
        return "utf-8", "utf-8-validated"
    except UnicodeDecodeError:
        pass
    try:
        raw.decode("cp1252")
        return "cp1252", "fallback"
    except UnicodeDecodeError:
        return "latin-1", "fallback"


# Decode the bytes, dropping a leading BOM when the codec name asks for it
def decode_text(raw, encoding):
    if encoding == "utf-8-sig":
        return raw.decode("utf-8-sig")
    return raw.decode(encoding)


# Count a delimiter on a line while ignoring anything inside double quotes
def count_unquoted(line, delimiter):
    total = 0
    in_quotes = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == '"':
            in_quotes = not in_quotes
        elif char == delimiter and not in_quotes:
            total += 1
        index += 1
    return total


# Score each candidate delimiter by how consistent its per-line count is
def sniff_delimiter(text, sample_lines=100):
    lines = [line for line in text.splitlines()[:sample_lines] if line.strip()]
    if not lines:
        return ",", {}
    scores = {}
    best = (",", -1)
    for candidate in CANDIDATE_DELIMITERS:
        counts = [count_unquoted(line, candidate) for line in lines]
        nonzero = [count for count in counts if count > 0]
        if not nonzero:
            scores[candidate] = 0
            continue
        common = max(set(nonzero), key=nonzero.count)
        consistency = sum(1 for count in counts if count == common)
        scores[candidate] = consistency
        if consistency > best[1]:
            best = (candidate, consistency)
    return best[0], scores


# Split text into records while remembering the physical line each one starts on
def iter_records(text, delimiter, quotechar='"'):
    lines = text.splitlines(keepends=True)
    buffer = []
    start_line = None
    for line_number, line in enumerate(lines, 1):
        if start_line is None:
            start_line = line_number
        buffer.append(line)
        chunk = "".join(buffer)
        # An odd number of quote characters means the record continues
        if chunk.count(quotechar) % 2 == 0:
            for record in csv.reader(
                io.StringIO(chunk), delimiter=delimiter, quotechar=quotechar
            ):
                yield start_line, record
            buffer = []
            start_line = None
    if buffer:
        for record in csv.reader(
            io.StringIO("".join(buffer)), delimiter=delimiter, quotechar=quotechar
        ):
            yield start_line or 0, record


# Build one finding dict, keeping the shape identical everywhere
def make_finding(code, severity, line, message):
    return {
        "code": code,
        "severity": severity,
        "line": line,
        "message": message,
    }


# Check how line endings are mixed across the file
def check_line_endings(raw):
    findings = []
    crlf = raw.count(b"\r\n")
    lone_cr = raw.count(b"\r") - crlf
    lone_lf = raw.count(b"\n") - crlf
    kinds = [name for name, count in (("crlf", crlf), ("lf", lone_lf), ("cr", lone_cr)) if count]
    if len(kinds) > 1:
        findings.append(
            make_finding(
                "CF007",
                WARNING,
                0,
                "mixed line endings: %s (crlf=%d, lf=%d, cr=%d)"
                % (", ".join(kinds), crlf, lone_lf, lone_cr),
            )
        )
    return findings


# Run the whole structural check over decoded text and return findings plus stats
def analyse(text, delimiter=",", quotechar='"', max_ragged=5):
    findings = []
    header = None
    width = 0
    row_count = 0
    ragged_total = 0
    empty_total = 0
    seen_headers = {}

    for line_number, record in iter_records(text, delimiter, quotechar):
        if not record or all(cell.strip() == "" for cell in record):
            empty_total += 1
            if empty_total <= max_ragged:
                findings.append(
                    make_finding(
                        "CF005", WARNING, line_number, "blank record (no fields)"
                    )
                )
            continue

        if header is None:
            header = record
            width = len(record)
            if width == 1:
                findings.append(
                    make_finding(
                        "CF009",
                        WARNING,
                        line_number,
                        "header has one column; the real delimiter may not be %r"
                        % delimiter,
                    )
                )
            for index, name in enumerate(record, 1):
                stripped = name.strip()
                if stripped == "":
                    findings.append(
                        make_finding(
                            "CF002", ERROR, line_number, "column %d has an empty header name" % index
                        )
                    )
                elif stripped != name:
                    findings.append(
                        make_finding(
                            "CF003",
                            WARNING,
                            line_number,
                            "column %d header has surrounding whitespace: %r" % (index, name),
                        )
                    )
                key = stripped.lower()
                if key in seen_headers:
                    findings.append(
                        make_finding(
                            "CF001",
                            ERROR,
                            line_number,
                            "duplicate header %r already used by column %d"
                            % (stripped, seen_headers[key]),
                        )
                    )
                else:
                    seen_headers[key] = index
            continue

        row_count += 1
        if len(record) != width:
            ragged_total += 1
            if ragged_total <= max_ragged:
                findings.append(
                    make_finding(
                        "CF004",
                        ERROR,
                        line_number,
                        "row has %d fields, header has %d" % (len(record), width),
                    )
                )

    if ragged_total > max_ragged:
        findings.append(
            make_finding(
                "CF004",
                ERROR,
                0,
                "%d more ragged rows not listed individually" % (ragged_total - max_ragged),
            )
        )
    if empty_total > max_ragged:
        findings.append(
            make_finding(
                "CF005",
                WARNING,
                0,
                "%d more blank records not listed individually" % (empty_total - max_ragged),
            )
        )

    stats = {
        "columns": width,
        "data_rows": row_count,
        "blank_records": empty_total,
        "ragged_rows": ragged_total,
    }
    return findings, stats


# Inspect one file and return a result dict shaped for text or JSON output
def inspect_file(path, delimiter=None, quotechar='"', max_bytes=DEFAULT_MAX_BYTES):
    raw = read_bytes(path, max_bytes)
    encoding, source = detect_encoding(raw)

    findings = []
    if b"\x00" in raw and not encoding.startswith(("utf-16", "utf-32")):
        findings.append(
            make_finding("CF006", ERROR, 0, "NUL bytes present; this is not plain text")
        )

    text = decode_text(raw, encoding)
    findings.extend(check_line_endings(raw))

    declared = delimiter is not None
    used_delimiter = delimiter
    score_table = {}
    if not declared:
        used_delimiter, score_table = sniff_delimiter(text)
        winner_score = score_table.get(used_delimiter, 0)
        other = max(
            (score for name, score in score_table.items() if name != used_delimiter),
            default=0,
        )
        if winner_score > 0 and winner_score == other:
            findings.append(
                make_finding(
                    "CF010",
                    WARNING,
                    0,
                    "delimiter guess %r ties with another candidate; pass --delimiter"
                    % used_delimiter,
                )
            )

    if encoding != "utf-8" and encoding != "utf-8-sig":
        findings.append(
            make_finding(
                "CF008",
                WARNING,
                0,
                "file is %s (%s); readers assuming UTF-8 will fail" % (encoding, source),
            )
        )

    structural, stats = analyse(text, used_delimiter, quotechar)
    findings.extend(structural)
    findings.sort(key=lambda item: (item["line"] == 0, item["line"]))

    return {
        "file": path,
        "bytes": len(raw),
        "encoding": encoding,
        "encoding_source": source,
        "delimiter": used_delimiter,
        "delimiter_declared": declared,
        "delimiter_scores": score_table,
        "columns": stats["columns"],
        "data_rows": stats["data_rows"],
        "blank_records": stats["blank_records"],
        "ragged_rows": stats["ragged_rows"],
        "ok": not any(item["severity"] == ERROR for item in findings),
        "findings": findings,
    }


# Render a result for a human, one header line then one line per finding
def format_text(result):
    delimiter_display = {
        "\t": "\\t",
        ",": ",",
        ";": ";",
        "|": "|",
    }.get(result["delimiter"], result["delimiter"])
    lines = []
    lines.append(
        "%s: %s, delimiter %r, %d columns, %d data rows"
        % (
            result["file"],
            result["encoding"],
            delimiter_display,
            result["columns"],
            result["data_rows"],
        )
    )
    if not result["findings"]:
        lines.append("  no structural problems found")
        return "\n".join(lines)
    for finding in result["findings"]:
        where = "line %d" % finding["line"] if finding["line"] else "file"
        lines.append(
            "  %-7s %s %s: %s"
            % (finding["severity"], finding["code"], where, finding["message"])
        )
    return "\n".join(lines)


# Parse arguments, inspect every target, print the report and set the exit code
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="csv-preflight",
        description="Report encoding, delimiter and structural problems in CSV files.",
    )
    parser.add_argument("targets", nargs="+", help="CSV files to inspect")
    parser.add_argument(
        "--delimiter",
        default=None,
        help="use this delimiter instead of guessing (accepts \\t for tab)",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="report format"
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="refuse files larger than this many bytes",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print nothing, rely on the exit code"
    )
    args = parser.parse_args(argv)

    delimiter = args.delimiter
    if delimiter == "\\t":
        delimiter = "\t"

    results = []
    exit_code = 0
    for path in args.targets:
        if not os.path.isfile(path):
            print("csv-preflight: not a file: %s" % path, file=sys.stderr)
            return 1
        try:
            result = inspect_file(path, delimiter=delimiter, max_bytes=args.max_bytes)
        except ValueError as error:
            print("csv-preflight: %s" % error, file=sys.stderr)
            return 1
        results.append(result)
        for finding in result["findings"]:
            if finding["severity"] == ERROR:
                exit_code = 2
                break

    if not args.quiet:
        if args.format == "json":
            payload = results[0] if len(results) == 1 else {"files": results}
            print(json.dumps(payload, indent=2))
        else:
            for result in results:
                print(format_text(result))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
