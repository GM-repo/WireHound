#!/usr/bin/env python3
"""
run_ndr_queries.py
==================

Execute the SQL in an NDR hunt workbook against a Zeek-derived SQLite database
and write the results back into the workbook.

For every row of every sheet that has a "SQL Query" column, the query in that
cell is run against the .sqlite file and its output is written into two new
columns on the same row: "num_output_rows" holds the first line of the output
(the row count and elapsed time) and "Query_results" holds everything after it.
Rows whose "SQL Query" cell reads "N/A - not observable in this schema" are
skipped without touching the database.

The finished workbook is always saved as ndr_sqlQueryResults.xlsx inside the
output path the user supplies.

Usage
-----
    python run_ndr_queries.py --xlsx  NDR_Characteristics_SQL_Queries.xlsx \\
                              --db    zeek.sqlite \\
                              --out   ./results

    # useful options
    --sheet Characteristics --sheet Per_Table   restrict to named sheets
    --format text|csv|json                      how results are rendered
    --max-rows 100                              result rows kept per query
    --timeout 60                                seconds before a query is aborted
    --max-cell-chars 32000                      hard cap (Excel's limit is 32767)

Notes
-----
* Uses Python's built-in `sqlite3` module, so no external sqlite3 binary is
  needed. The database is opened read-only (`mode=ro`) so a query can never
  modify the evidence.
* Long-running queries are aborted by a progress handler rather than being
  left to run forever - several of the hunt queries are self-joins that can be
  expensive on a large capture.
* openpyxl does not preserve cached formula results. If the input workbook has
  a sheet containing formulas (the Coverage sheet does), those cells will read
  as empty until the workbook is opened and recalculated in Excel or
  LibreOffice. The formulas themselves are preserved.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sqlite3
import sys
import time
from typing import Any, Iterable, Sequence

try:
    from openpyxl import load_workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
except ImportError:  # pragma: no cover
    sys.exit("openpyxl is required:  pip install openpyxl")


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

QUERY_COLUMN = "SQL Query"
ROWCOUNT_COLUMN = "num_output_rows"
RESULT_COLUMN = "Query_results"
OUTPUT_FILENAME = "ndr_sqlQueryResults.xlsx"

# Cells matching any of these (after normalisation) are never executed.
SKIP_VALUES = {
    "n/a - not observable in this schema",
    "n/a - not in schema",
    "n/a",
}

EXCEL_MAX_CELL = 32767

# Characters XML 1.0 forbids, so openpyxl refuses to write them into a cell.
# Tab, newline and carriage return are legal and are deliberately not listed.
ILLEGAL_XLSX_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]")

# Raw packet bytes are shown as an ASCII/hex preview of at most this many bytes.
BLOB_PREVIEW_BYTES = 96


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def normalise(value: Any) -> str:
    """Lower-case, collapse whitespace, and normalise dash variants."""
    if value is None:
        return ""
    text = str(value).replace("–", "-").replace("—", "-")
    return re.sub(r"\s+", " ", text).strip().lower()


def should_skip(cell_value: Any) -> tuple[bool, str]:
    """Return (skip?, reason). Blank cells and the N/A sentinel are skipped."""
    norm = normalise(cell_value)
    if not norm:
        return True, "empty SQL Query cell"
    if norm in SKIP_VALUES or norm.startswith("n/a"):
        return True, "marked not observable in this schema"
    return False, ""


def find_header(ws, name: str) -> int | None:
    """Column index (1-based) of `name` in row 1, matched leniently."""
    target = normalise(name)
    for cell in ws[1]:
        if normalise(cell.value) == target:
            return cell.column
    return None


def clean_sql(sql: str) -> str:
    """Strip trailing whitespace and a single trailing semicolon."""
    return sql.strip().rstrip(";").strip()


def sanitise_for_xlsx(text: Any) -> str:
    """Make `text` safe to store in a worksheet cell.

    Zeek logs carry raw packet bytes in fields such as analyzer.packet_segment,
    dpd.packet_segment and unknown_protocols.first_bytes. Those bytes routinely
    include control characters, which XML 1.0 forbids and openpyxl rejects with
    IllegalCharacterError. Rather than dropping them - they are evidence - each
    offending character is escaped to a readable \\xNN form.
    """
    if text is None:
        return ""
    return ILLEGAL_XLSX_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", str(text))


def normalise_value(value: Any) -> Any:
    """Convert a SQLite value into something renderable and XML-safe.

    Numbers and None pass through untouched so JSON output stays typed. BLOBs
    become a bounded hex preview; text is escaped by sanitise_for_xlsx.
    """
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        head = raw[:BLOB_PREVIEW_BYTES].hex()
        return f"0x{head}" if len(raw) <= BLOB_PREVIEW_BYTES \
            else f"0x{head}... ({len(raw)} bytes)"
    return sanitise_for_xlsx(value)


def write_cell(ws, row: int, column: int, value: Any):
    """Write a value, guaranteeing it cannot trip IllegalCharacterError."""
    return ws.cell(row=row, column=column, value=sanitise_for_xlsx(value))


def split_first_line(text: str) -> tuple[str, str]:
    """Split `text` into its first line and everything after it.

    The first line of a rendered result is the row count and elapsed time; the
    remainder is the result set itself. They go into separate columns.
    """
    head, _, rest = str(text).partition("\n")
    return head, rest


def _rgb(color) -> str | None:
    """Extract an 'AARRGGBB' string from an openpyxl colour, or None."""
    value = getattr(color, "rgb", None)
    return value if isinstance(value, str) else None


def style_like_header(cell, template) -> None:
    """Make `cell` look like the existing header `template`.

    Purely cosmetic, so any failure is swallowed - a styling problem must never
    stop the queries from running.
    """
    try:
        cell.font = Font(
            name=template.font.name or "Arial",
            size=template.font.size or 10,
            bold=True,
            color=_rgb(template.font.color) or "FFFFFF",
        )
        fill_rgb = _rgb(getattr(template.fill, "fgColor", None))
        if fill_rgb and template.fill.patternType == "solid":
            cell.fill = PatternFill("solid", fgColor=fill_rgb)
        cell.alignment = Alignment(
            vertical="center", horizontal="left", wrap_text=True
        )
    except Exception:  # noqa: BLE001 - cosmetic only
        cell.font = Font(bold=True)


# --------------------------------------------------------------------------- #
# result rendering
# --------------------------------------------------------------------------- #

def render_text(columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Fixed-width table, readable inside a spreadsheet cell."""
    stringify = lambda v: "" if v is None else str(v).replace("\n", " ").replace("\r", " ")
    table = [list(columns)] + [[stringify(v) for v in r] for r in rows]
    widths = [
        min(max(len(row[i]) for row in table), 40)
        for i in range(len(columns))
    ]
    lines = []
    for idx, row in enumerate(table):
        lines.append(" | ".join(
            cell[:widths[i]].ljust(widths[i]) for i, cell in enumerate(row)
        ).rstrip())
        if idx == 0:
            lines.append("-+-".join("-" * w for w in widths))
    return "\n".join(lines)


def render_csv(columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    writer.writerows(["" if v is None else v for v in r] for r in rows)
    return buf.getvalue().rstrip("\n")


def render_json(columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    return json.dumps(
        [dict(zip(columns, r)) for r in rows], indent=2, default=str
    )


RENDERERS = {"text": render_text, "csv": render_csv, "json": render_json}


def format_result(
    columns: Sequence[str],
    rows: Sequence[Sequence[Any]],
    truncated: bool,
    elapsed: float,
    fmt: str,
    max_chars: int,
) -> str:
    if not columns:
        return "OK - statement returned no result set."
    columns = [sanitise_for_xlsx(c) for c in columns]
    if not rows:
        header = f"0 rows  ({elapsed:.2f}s)"
        return f"{header}\ncolumns: {', '.join(columns)}"

    # Escape control characters and preview BLOBs before anything is rendered.
    rows = [[normalise_value(v) for v in r] for r in rows]

    count = f"{len(rows)}+" if truncated else str(len(rows))
    header = f"{count} row(s)  ({elapsed:.2f}s)"
    if truncated:
        header += f"  [showing first {len(rows)}]"

    body = RENDERERS[fmt](columns, rows)
    text = f"{header}\n{body}"

    if len(text) > max_chars:
        text = text[: max_chars - 40].rstrip() + "\n... [truncated to fit cell]"
    return text


# --------------------------------------------------------------------------- #
# query execution
# --------------------------------------------------------------------------- #

class QueryRunner:
    """Runs statements read-only, with a wall-clock abort."""

    def __init__(self, db_path: str, timeout: float, max_rows: int):
        if not os.path.isfile(db_path):
            raise FileNotFoundError(f"database not found: {db_path}")
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        self.conn = sqlite3.connect(uri, uri=True, timeout=10)
        self.conn.row_factory = None
        # Zeek stores raw packet fragments (analyzer.packet_segment,
        # dpd.packet_segment, unknown_protocols.first_bytes) in TEXT columns.
        # Those are frequently not valid UTF-8, and the default text factory
        # aborts the whole query with "Could not decode to UTF-8". Decoding with
        # backslashreplace keeps every byte visible as \xNN instead of losing
        # the result set.
        self.conn.text_factory = lambda raw: raw.decode("utf-8", "backslashreplace")
        self.timeout = timeout
        self.max_rows = max_rows

    def close(self) -> None:
        self.conn.close()

    def _arm_guard(self) -> None:
        deadline = time.monotonic() + self.timeout
        self.conn.set_progress_handler(
            lambda: 1 if time.monotonic() > deadline else 0, 5000
        )

    def run(self, sql: str) -> tuple[list[str], list[tuple], bool, float, str | None]:
        """Return (columns, rows, truncated, elapsed_seconds, error_or_None)."""
        started = time.monotonic()
        self._arm_guard()
        try:
            cur = self.conn.execute(sql)
            columns = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchmany(self.max_rows) if columns else []
            truncated = bool(columns) and cur.fetchone() is not None
            cur.close()
            return columns, rows, truncated, time.monotonic() - started, None
        except sqlite3.OperationalError as exc:
            msg = str(exc)
            if "interrupted" in msg.lower():
                msg = f"aborted after {self.timeout:g}s timeout"
            return [], [], False, time.monotonic() - started, msg
        except sqlite3.Error as exc:
            return [], [], False, time.monotonic() - started, str(exc)
        finally:
            self.conn.set_progress_handler(None, 0)


# --------------------------------------------------------------------------- #
# workbook processing
# --------------------------------------------------------------------------- #

def process_sheet(ws, runner: QueryRunner, args) -> dict[str, int]:
    tally = {"executed": 0, "skipped": 0, "errors": 0, "empty": 0}

    q_col = find_header(ws, QUERY_COLUMN)
    if q_col is None:
        print(f"  [{ws.title}] no '{QUERY_COLUMN}' column - left unchanged")
        return tally

    def ensure_column(name: str, width: int) -> int:
        """Index of `name`, appending it as a styled header if absent."""
        col = find_header(ws, name)
        if col is None:
            col = ws.max_column + 1
            style_like_header(write_cell(ws, 1, col, name),
                              ws.cell(row=1, column=q_col))
            ws.column_dimensions[get_column_letter(col)].width = width
        return col

    n_col = ensure_column(ROWCOUNT_COLUMN, 26)
    r_col = ensure_column(RESULT_COLUMN, 110)
    if ws.auto_filter.ref:
        last = get_column_letter(max(n_col, r_col, ws.max_column))
        ws.auto_filter.ref = f"A1:{last}{ws.max_row}"

    total = ws.max_row - 1
    for row in range(2, ws.max_row + 1):
        sql_value = ws.cell(row=row, column=q_col).value
        skip, reason = should_skip(sql_value)

        if skip:
            tally["skipped" if "not observable" in reason else "empty"] += 1
            result_text = f"SKIPPED\n{reason}"
        else:
            sql = clean_sql(str(sql_value))
            cols, rows, trunc, elapsed, err = runner.run(sql)
            if err:
                tally["errors"] += 1
                result_text = f"ERROR  ({elapsed:.2f}s)\n{err}"
            else:
                tally["executed"] += 1
                result_text = format_result(
                    cols, rows, trunc, elapsed, args.format, args.max_cell_chars
                )

        row_count, body = split_first_line(result_text)
        for col, value in ((n_col, row_count), (r_col, body)):
            cell = write_cell(ws, row, col, value)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            cell.font = Font(name="Courier New", size=9)

        if sys.stdout.isatty() and (args.verbose or (row - 1) % 25 == 0):
            print(f"    [{ws.title}] row {row - 1}/{total}", end="\r", flush=True)

    print(
        f"    [{ws.title}] {total} rows: "
        f"{tally['executed']} executed, {tally['skipped']} skipped (N/A), "
        f"{tally['empty']} blank, {tally['errors']} errors" + " " * 12
    )
    return tally


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Run the SQL Query column of an NDR workbook against a "
                    "Zeek SQLite database and record the results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--xlsx", required=True, help="input .xlsx workbook")
    p.add_argument("--db", required=True, help="input .sqlite database")
    p.add_argument("--out", required=True,
                   help=f"output directory; the file is always written as {OUTPUT_FILENAME}")
    p.add_argument("--sheet", action="append", default=None,
                   help="only process this sheet (repeatable); default is every sheet")
    p.add_argument("--format", choices=sorted(RENDERERS), default="text",
                   help="how result sets are rendered into the cell")
    p.add_argument("--max-rows", type=int, default=100,
                   help="maximum result rows recorded per query")
    p.add_argument("--max-cell-chars", type=int, default=32000,
                   help=f"cell length cap (Excel's own limit is {EXCEL_MAX_CELL})")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="seconds before an individual query is aborted")
    p.add_argument("-v", "--verbose", action="store_true", help="per-row progress")
    args = p.parse_args(argv)

    if args.max_cell_chars > EXCEL_MAX_CELL:
        p.error(f"--max-cell-chars cannot exceed {EXCEL_MAX_CELL}")
    if args.max_rows < 1:
        p.error("--max-rows must be at least 1")
    if not os.path.isfile(args.xlsx):
        p.error(f"workbook not found: {args.xlsx}")

    # Accept either a directory or a file path for --out; the name is fixed.
    out_dir = args.out
    if os.path.splitext(out_dir)[1].lower() == ".xlsx":
        out_dir = os.path.dirname(out_dir) or "."
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, OUTPUT_FILENAME)

    print(f"workbook : {args.xlsx}")
    print(f"database : {args.db}")
    print(f"output   : {out_path}\n")

    try:
        runner = QueryRunner(args.db, args.timeout, args.max_rows)
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(f"cannot open database: {exc}", file=sys.stderr)
        return 2

    wb = load_workbook(args.xlsx)
    wanted = set(args.sheet) if args.sheet else None
    if wanted:
        missing = wanted - set(wb.sheetnames)
        if missing:
            print(f"no such sheet(s): {', '.join(sorted(missing))}", file=sys.stderr)
            runner.close()
            return 2

    totals = {"executed": 0, "skipped": 0, "errors": 0, "empty": 0}
    try:
        for ws in wb.worksheets:
            if wanted and ws.title not in wanted:
                continue
            for key, val in process_sheet(ws, runner, args).items():
                totals[key] += val
    finally:
        runner.close()

    wb.save(out_path)

    print(
        f"\ndone: {totals['executed']} queries executed, "
        f"{totals['skipped']} skipped as not observable, "
        f"{totals['empty']} blank, {totals['errors']} errors"
    )
    print(f"saved: {out_path}")
    return 1 if totals["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
