#!/usr/bin/env python3
"""
analyse_with_gemini.py
======================

Adjudicate NDR hunt results with Gemini.

Takes the workbook produced by run_ndr_queries.py together with the network
topology (.gexf) and a written description of the network (.txt), and asks
Gemini, one row at a time, whether the SQL output is evidence that the attack
characteristic was actually observed on this network.

Per row the model receives:
  * the attack characteristic                 (column "characteristic")
  * the SQL query that hunted for it          (column "SQL Query")
  * the analyst notes and tuning guidance     (column "Notes & Tuning")
  * the number of rows the query returned     (column "num_output_rows")
  * the query output itself                   (column "Query_results")
  * the network topology, summarised from the .gexf
  * the network description, read from the .txt
  * a description of what each of those inputs is

Gemini answers Yes or No plus a two-sentence explanation. The verdict is
written to a new column "Malicious" and the reasoning to "Gemini explanation".

Rows whose "num_output_rows" begins with "0 rows" or "ERROR" are ignored - they
carry no evidence to judge. "SKIPPED" is ignored on the same grounds; drop it
from --skip-prefix if you would rather those rows were sent.

The result is written to sqlQueryAnalysis.xlsx inside the path you supply.

Usage
-----
    export GEMINI_API_KEY=...
    python analyse_with_gemini.py --xlsx ndr_sqlQueryResults.xlsx \\
                                  --gexf topology.gexf \\
                                  --txt  network_description.txt \\
                                  --out  ./analysis

    # useful options
    --model gemini-3.7-flash     model id (default shown)
    --dry-run                    build every prompt, call nothing, print the first
    --limit 20                   only adjudicate the first N eligible rows
    --resume                     leave rows that already have a Malicious verdict
    --sleep 1.0                  seconds between calls, for rate limits
    --retries 4                  attempts per row on transient API errors

Requirements
------------
openpyxl only - already needed by run_ndr_queries.py. The Gemini call is made
against the REST API using urllib from the standard library, so no SDK
(google-genai or otherwise) has to be installed. HTTPS_PROXY / HTTP_PROXY are
honoured automatically by urllib.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Callable, Sequence

try:
    from openpyxl import load_workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
except ImportError:  # pragma: no cover
    sys.exit("openpyxl is required:  pip install openpyxl")


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

COL_CHARACTERISTIC = "characteristic"
COL_SQL = "SQL Query"
COL_NOTES = "Notes & Tuning"
COL_NUMROWS = "num_output_rows"
COL_RESULTS = "Query_results"

COL_VERDICT = "Malicious"
COL_EXPLANATION = "Gemini explanation"

OUTPUT_FILENAME = "sqlQueryAnalysis.xlsx"
DEFAULT_MODEL = "gemini-3.7-flash"
API_HOST = "https://generativelanguage.googleapis.com"

# num_output_rows values starting with any of these carry no evidence to judge.
DEFAULT_SKIP_PREFIXES = ("0 rows", "error", "skipped")

ILLEGAL_XLSX_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]")

VERDICT_FILL = {
    "yes": PatternFill("solid", fgColor="FFC7CE"),
    "no": PatternFill("solid", fgColor="C6EFCE"),
}

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "malicious": {
            "type": "string",
            "enum": ["Yes", "No"],
            "description": "Yes if the SQL output is evidence the attack "
                           "characteristic was observed, otherwise No.",
        },
        "explanation": {
            "type": "string",
            "description": "Exactly two sentences justifying the verdict.",
        },
    },
    "required": ["malicious", "explanation"],
}

SYSTEM_INSTRUCTION = """\
You are a senior network detection and response analyst reviewing the output of
a threat-hunting query against Zeek network logs.

Decide one thing only: does the query output constitute evidence that the named
attack characteristic was actually observed on this network?

How to judge:
- The query returning rows is not by itself proof. Most hunt queries have benign
  twins, and the notes column usually names them. Weigh the notes seriously.
- Use the network topology and description to decide what is normal here. A host
  behaving like a server is unremarkable if the topology says it is one.
- Consider volume, direction, timing and which hosts are involved, not just the
  row count. A handful of rows consistent with the documented architecture is
  usually No; a pattern that contradicts it is usually Yes.
- Answer Yes when the evidence supports the characteristic being present.
  Answer No when the rows are better explained by normal operation, or when the
  output is too thin or too ambiguous to support the claim.
- Be decisive. Do not hedge with "possibly" or refuse to choose.

Reply with exactly two fields: "malicious" (the string Yes or No) and
"explanation" (exactly two sentences, plain and specific, naming the concrete
evidence that drove the verdict).\
"""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def normalise(value: Any) -> str:
    """Lower-case, collapse whitespace, normalise dash variants."""
    if value is None:
        return ""
    text = str(value).replace("–", "-").replace("—", "-")
    return re.sub(r"\s+", " ", text).strip().lower()


def sanitise_for_xlsx(text: Any) -> str:
    """Escape characters XML 1.0 forbids so openpyxl will accept the value."""
    if text is None:
        return ""
    return ILLEGAL_XLSX_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", str(text))


def find_header(ws, name: str) -> int | None:
    """Column index (1-based) of `name` in row 1.

    Matched case-insensitively, falling back to a prefix match so a header like
    "Characteristic (adversarial / unusual behaviour)" still answers to
    "characteristic".
    """
    target = normalise(name)
    headers = [(cell.column, normalise(cell.value)) for cell in ws[1]]
    for column, header in headers:
        if header == target:
            return column
    for column, header in headers:
        if header.startswith(target):
            return column
    return None


def clip(text: Any, limit: int, label: str = "") -> str:
    """Trim `text` to `limit` characters, saying so when it happens."""
    s = "" if text is None else str(text)
    if len(s) <= limit:
        return s
    note = f"\n... [{label}truncated, {len(s)} characters total]"
    return s[: max(limit - len(note), 0)].rstrip() + note


# --------------------------------------------------------------------------- #
# context building
# --------------------------------------------------------------------------- #

def _tag(element) -> str:
    """Local tag name, with any XML namespace stripped."""
    return element.tag.rsplit("}", 1)[-1]


def summarise_gexf(path: str, max_chars: int) -> str:
    """Render a .gexf topology as compact text.

    The raw XML is verbose and mostly boilerplate, so nodes, their attributes
    and the edge list are extracted instead. If the file cannot be parsed the
    reason is returned, so the model is told the topology is unavailable rather
    than being handed nothing.
    """
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        return f"[topology could not be parsed: {exc}]"

    attr_titles: dict[str, str] = {}
    for element in root.iter():
        if _tag(element) == "attribute":
            aid = element.get("id")
            if aid:
                attr_titles[aid] = element.get("title", aid)

    nodes: list[str] = []
    edges: list[str] = []
    for element in root.iter():
        name = _tag(element)
        if name == "node":
            nid = element.get("id", "?")
            label = element.get("label", "")
            attrs = []
            for value in element.iter():
                if _tag(value) == "attvalue":
                    key = attr_titles.get(value.get("for", ""), value.get("for", ""))
                    attrs.append(f"{key}={value.get('value', '')}")
            entry = f"  - {nid}" + (f' "{label}"' if label else "")
            if attrs:
                entry += "  [" + ", ".join(attrs) + "]"
            nodes.append(entry)
        elif name == "edge":
            src, dst = element.get("source", "?"), element.get("target", "?")
            extra = [
                f"{k}={element.get(k)}"
                for k in ("label", "weight", "kind", "type")
                if element.get(k)
            ]
            edges.append(f"  - {src} -> {dst}" + ("  [" + ", ".join(extra) + "]" if extra else ""))

    graph = next((e for e in root.iter() if _tag(e) == "graph"), None)
    header = [f"Nodes: {len(nodes)}   Edges: {len(edges)}"]
    if graph is not None:
        mode = graph.get("mode")
        etype = graph.get("defaultedgetype")
        if mode or etype:
            header.append(f"Graph: mode={mode or 'static'}, edge type={etype or 'undirected'}")

    body = "\n".join(header + ["", "NODES:"] + nodes + ["", "EDGES:"] + edges)
    return clip(body, max_chars, "topology ")


def read_text_file(path: str, max_chars: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return clip(handle.read().strip(), max_chars, "description ")
    except OSError as exc:
        return f"[description could not be read: {exc}]"


def build_prompt(row: dict[str, str], topology: str, description: str) -> str:
    """Assemble the per-row prompt, with every input clearly labelled."""
    return f"""\
Below is one row from a network threat-hunting workbook, plus context describing
the network the traffic was captured on. Decide whether the query output is
evidence that the attack characteristic was observed.

================================================================
CONTEXT 1 - NETWORK TOPOLOGY
What this is: a summary of a GEXF graph file describing the monitored network.
Nodes are hosts or devices, edges are the links or communication paths between
them; node attributes carry role, zone or address information where present.
Use it to judge whether the hosts in the query output are behaving consistently
with their place in the network.
----------------------------------------------------------------
{topology}

================================================================
CONTEXT 2 - NETWORK DESCRIPTION
What this is: an analyst's written description of the same network - its
purpose, segments, expected services and normal traffic patterns. Use it to
decide what counts as normal here.
----------------------------------------------------------------
{description}

================================================================
THE ROW UNDER REVIEW
----------------------------------------------------------------
ATTACK CHARACTERISTIC
What this is: the adversarial behaviour the query is hunting for.
{row['characteristic']}

----------------------------------------------------------------
SQL QUERY
What this is: the query that was run against the Zeek log database to look for
that characteristic. Read it to understand exactly what the output rows mean.
{row['sql']}

----------------------------------------------------------------
NOTES AND TUNING
What this is: the analyst's guidance on this query - its thresholds, its known
benign twins, and what would raise or lower confidence. Weigh this heavily.
{row['notes']}

----------------------------------------------------------------
NUMBER OF ROWS RETURNED
{row['num_rows']}

----------------------------------------------------------------
QUERY OUTPUT
What this is: the rows the query returned. The first line is the column header,
followed by a separator, then the data rows.
{row['results']}

================================================================
Does this output show that the attack characteristic was observed on this
network? Answer Yes or No, and explain in exactly two sentences."""


# --------------------------------------------------------------------------- #
# Gemini client
# --------------------------------------------------------------------------- #

class ApiUnsupported(Exception):
    """This endpoint or request shape is not available - try the next one."""


class ApiTransient(Exception):
    """Rate limit, timeout or server error - the same request may yet succeed."""


class ApiFatal(Exception):
    """Bad credentials or a rejected request - retrying will not help."""


def _openapi_schema(schema: Any) -> Any:
    """Convert JSON Schema types to the uppercase enum the legacy API wants."""
    if isinstance(schema, dict):
        return {k: (v.upper() if k == "type" and isinstance(v, str)
                    else _openapi_schema(v))
                for k, v in schema.items()}
    if isinstance(schema, list):
        return [_openapi_schema(item) for item in schema]
    return schema


def _extract_text(payload: dict) -> str:
    """Pull the generated text out of whichever response shape came back."""
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]
    if isinstance(payload.get("outputText"), str):
        return payload["outputText"]

    # Interactions API: output[].content[].text
    chunks: list[str] = []
    for item in payload.get("output", []) or []:
        for part in (item.get("content") or []) if isinstance(item, dict) else []:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    if chunks:
        return "".join(chunks)

    # generateContent: candidates[0].content.parts[].text
    for candidate in payload.get("candidates", []) or []:
        parts = (candidate.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        if text:
            return text

    raise ApiUnsupported(f"no text field in response: {json.dumps(payload)[:300]}")


class GeminiJudge:
    """Calls the Gemini REST API directly, using only the standard library.

    Google has moved from generateContent to the Interactions API, and the
    structured-output request shape changed with it. Rather than pinning one
    convention, each is tried in turn on the first row and whichever the account
    and model actually accept is remembered for the rest of the run.
    """

    def __init__(self, api_key: str, model: str, retries: int, sleep: float,
                 http_timeout: float = 120.0):
        self.api_key = api_key
        self.model = model
        self.retries = max(1, retries)
        self.sleep = sleep
        self.http_timeout = http_timeout
        self._strategy: tuple[str, Callable[[str], str]] | None = None

    # -- transport ----------------------------------------------------------- #

    def _post(self, url: str, body: dict) -> dict:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
                "User-Agent": "ndr-hunt-analyser/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.http_timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            if exc.code in (400, 404):
                # Unknown field, unsupported schema, or no such endpoint/model.
                raise ApiUnsupported(f"HTTP {exc.code}: {detail}") from exc
            if exc.code in (401, 403):
                raise ApiFatal(f"HTTP {exc.code} - check the API key: {detail}") from exc
            if exc.code == 429 or exc.code >= 500:
                raise ApiTransient(f"HTTP {exc.code}: {detail}") from exc
            raise ApiFatal(f"HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ApiTransient(f"network error: {exc.reason}") from exc
        except TimeoutError as exc:
            raise ApiTransient(f"request timed out after {self.http_timeout:g}s") from exc
        except json.JSONDecodeError as exc:
            raise ApiTransient(f"malformed JSON in response: {exc}") from exc

    # -- calling conventions, newest first ----------------------------------- #

    def _interactions(self, version: str, prompt: str) -> str:
        return _extract_text(self._post(
            f"{API_HOST}/{version}/interactions",
            {
                "model": self.model,
                "input": f"{SYSTEM_INSTRUCTION}\n\n{prompt}",
                "response_format": {
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": RESPONSE_SCHEMA,
                },
            },
        ))

    def _generate_content(self, prompt: str, generation_config: dict) -> str:
        return _extract_text(self._post(
            f"{API_HOST}/v1beta/models/{self.model}:generateContent",
            {
                "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": generation_config,
            },
        ))

    def _via_interactions_v1(self, prompt: str) -> str:
        return self._interactions("v1", prompt)

    def _via_interactions_v1beta(self, prompt: str) -> str:
        return self._interactions("v1beta", prompt)

    def _via_generate_content_schema(self, prompt: str) -> str:
        return self._generate_content(prompt, {
            "responseMimeType": "application/json",
            "responseSchema": _openapi_schema(RESPONSE_SCHEMA),
            "temperature": 0,
        })

    def _via_generate_content_json(self, prompt: str) -> str:
        return self._generate_content(prompt, {
            "responseMimeType": "application/json",
            "temperature": 0,
        })

    def _via_generate_content_plain(self, prompt: str) -> str:
        return self._generate_content(
            prompt + '\n\nReply with JSON only, exactly: '
                     '{"malicious": "Yes" or "No", "explanation": "two sentences"}',
            {"temperature": 0},
        )

    STRATEGY_NAMES = (
        ("v1 interactions", "_via_interactions_v1"),
        ("v1beta interactions", "_via_interactions_v1beta"),
        ("generateContent + responseSchema", "_via_generate_content_schema"),
        ("generateContent + JSON mime type", "_via_generate_content_json"),
        ("generateContent plain text", "_via_generate_content_plain"),
    )

    # -- public API ----------------------------------------------------------- #

    def _raw_call(self, prompt: str) -> str:
        if self._strategy is not None:
            return self._strategy[1](prompt)

        problems = []
        for name, attr in self.STRATEGY_NAMES:
            func = getattr(self, attr)
            try:
                text = func(prompt)
            except ApiUnsupported as exc:
                problems.append(f"{name}: {exc}")
                continue
            self._strategy = (name, func)
            print(f"  (using {name})")
            return text
        raise ApiFatal(
            "no supported Gemini REST convention worked:\n    "
            + "\n    ".join(problems)
        )

    def judge(self, prompt: str) -> tuple[str, str]:
        """Return (verdict, explanation). Raises only after every retry fails."""
        last_error = None
        for attempt in range(1, self.retries + 1):
            try:
                return parse_verdict(self._raw_call(prompt))
            except ApiFatal:
                raise
            except Exception as exc:  # noqa: BLE001 - surfaced to the caller
                last_error = exc
                if attempt < self.retries:
                    backoff = self.sleep * (2 ** (attempt - 1)) + 1.0
                    print(f"    attempt {attempt} failed ({exc}); "
                          f"retrying in {backoff:.1f}s")
                    time.sleep(backoff)
        raise RuntimeError(str(last_error))


def parse_verdict(text: str) -> tuple[str, str]:
    """Pull the verdict and explanation out of the model's reply."""
    if not text:
        raise ValueError("empty response from the model")

    body = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", body, re.S)
    if fenced:
        body = fenced.group(1).strip()

    data = None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        brace = re.search(r"\{.*\}", body, re.S)
        if brace:
            try:
                data = json.loads(brace.group())
            except json.JSONDecodeError:
                data = None

    if isinstance(data, dict):
        verdict = str(data.get("malicious", "")).strip()
        explanation = str(data.get("explanation", "")).strip()
    else:
        # Last resort: the model answered in prose.
        verdict = ""
        explanation = body

    lowered = verdict.lower()
    if lowered.startswith("y"):
        verdict = "Yes"
    elif lowered.startswith("n"):
        verdict = "No"
    else:
        found = re.search(r"\b(yes|no)\b", explanation[:200], re.I)
        if not found:
            raise ValueError(f"could not read a Yes/No verdict from: {body[:200]}")
        verdict = found.group(1).capitalize()

    return verdict, explanation or "(no explanation returned)"


# --------------------------------------------------------------------------- #
# workbook processing
# --------------------------------------------------------------------------- #

def ensure_column(ws, name: str, width: int, template_col: int) -> int:
    """Index of column `name`, appending it with header styling if absent."""
    col = find_header(ws, name)
    if col is not None:
        return col
    col = ws.max_column + 1
    head = ws.cell(row=1, column=col, value=name)
    template = ws.cell(row=1, column=template_col)
    try:
        rgb = getattr(template.font.color, "rgb", None)
        head.font = Font(name=template.font.name or "Arial",
                         size=template.font.size or 10, bold=True,
                         color=rgb if isinstance(rgb, str) else "FFFFFF")
        fill_rgb = getattr(getattr(template.fill, "fgColor", None), "rgb", None)
        if isinstance(fill_rgb, str) and template.fill.patternType == "solid":
            head.fill = PatternFill("solid", fgColor=fill_rgb)
        head.alignment = Alignment(vertical="center", wrap_text=True)
    except Exception:  # noqa: BLE001 - cosmetic only
        head.font = Font(bold=True)
    ws.column_dimensions[get_column_letter(col)].width = width
    return col


def process_sheet(ws, judge, topology: str, description: str, args) -> dict[str, int]:
    tally = {"judged": 0, "skipped": 0, "failed": 0, "resumed": 0,
             "yes": 0, "no": 0}

    cols = {
        "characteristic": find_header(ws, COL_CHARACTERISTIC),
        "sql": find_header(ws, COL_SQL),
        "notes": find_header(ws, COL_NOTES),
        "num_rows": find_header(ws, COL_NUMROWS),
        "results": find_header(ws, COL_RESULTS),
    }
    missing = [name for name, idx in cols.items() if idx is None]
    if missing:
        print(f"  [{ws.title}] missing column(s) "
              f"{', '.join(missing)} - sheet left unchanged")
        return tally

    v_col = ensure_column(ws, COL_VERDICT, 12, cols["characteristic"])
    e_col = ensure_column(ws, COL_EXPLANATION, 70, cols["characteristic"])
    if ws.auto_filter.ref:
        ws.auto_filter.ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"

    def cell_text(row: int, key: str) -> str:
        value = ws.cell(row=row, column=cols[key]).value
        return "" if value is None else str(value)

    eligible = []
    for row in range(2, ws.max_row + 1):
        marker = normalise(cell_text(row, "num_rows"))
        if not marker or marker.startswith(tuple(args.skip_prefix)):
            tally["skipped"] += 1
            continue
        if args.resume and str(ws.cell(row=row, column=v_col).value or "").strip():
            tally["resumed"] += 1
            continue
        eligible.append(row)

    if args.limit:
        eligible = eligible[: args.limit]

    print(f"  [{ws.title}] {len(eligible)} row(s) to adjudicate, "
          f"{tally['skipped']} ignored"
          + (f", {tally['resumed']} already done" if tally["resumed"] else ""))

    for position, row in enumerate(eligible, start=1):
        payload = {
            "characteristic": cell_text(row, "characteristic"),
            "sql": cell_text(row, "sql"),
            "notes": cell_text(row, "notes"),
            "num_rows": cell_text(row, "num_rows"),
            "results": clip(cell_text(row, "results"),
                            args.max_result_chars, "output "),
        }
        prompt = build_prompt(payload, topology, description)

        if args.dry_run:
            if position == 1:
                print("\n" + "=" * 70)
                print(f"DRY RUN - prompt for {ws.title} row {row} "
                      f"({len(prompt)} characters)")
                print("=" * 70)
                print(prompt)
                print("=" * 70 + "\n")
            verdict, explanation = "", "[dry run - no Gemini call made]"
        else:
            try:
                verdict, explanation = judge.judge(prompt)
                tally["judged"] += 1
                tally[verdict.lower()] += 1
            except ApiFatal:
                raise           # bad key or no usable endpoint - stop the run
            except Exception as exc:  # noqa: BLE001
                tally["failed"] += 1
                verdict, explanation = "", f"[Gemini call failed: {exc}]"

        v_cell = ws.cell(row=row, column=v_col, value=sanitise_for_xlsx(verdict))
        v_cell.alignment = Alignment(vertical="top", horizontal="center")
        v_cell.font = Font(name="Arial", size=10, bold=True)
        if verdict.lower() in VERDICT_FILL:
            v_cell.fill = VERDICT_FILL[verdict.lower()]

        e_cell = ws.cell(row=row, column=e_col, value=sanitise_for_xlsx(explanation))
        e_cell.alignment = Alignment(vertical="top", wrap_text=True)
        e_cell.font = Font(name="Arial", size=9)

        label = payload["characteristic"][:58].replace("\n", " ")
        print(f"    {position}/{len(eligible)}  row {row}  "
              f"{verdict or '-':<3}  {label}")

        if args.save_every and position % args.save_every == 0:
            args._save_callback()

        if not args.dry_run and args.sleep and position < len(eligible):
            time.sleep(args.sleep)

    return tally


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Ask Gemini whether each hunt query's output shows the "
                    "attack characteristic was observed.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--xlsx", required=True, help="workbook from run_ndr_queries.py")
    p.add_argument("--gexf", required=True, help="network topology (.gexf)")
    p.add_argument("--txt", required=True, help="network description (.txt)")
    p.add_argument("--out", required=True,
                   help=f"output directory; written as {OUTPUT_FILENAME}")
    p.add_argument("--model", default=DEFAULT_MODEL, help="Gemini model id")
    p.add_argument("--api-key", default=None,
                   help="Gemini API key; defaults to $GEMINI_API_KEY or $GOOGLE_API_KEY")
    p.add_argument("--sheet", action="append", default=None,
                   help="only process this sheet (repeatable)")
    p.add_argument("--skip-prefix", action="append", default=None,
                   help="ignore rows whose num_output_rows starts with this "
                        f"(repeatable; default: {', '.join(DEFAULT_SKIP_PREFIXES)})")
    p.add_argument("--limit", type=int, default=0,
                   help="adjudicate at most this many rows per sheet (0 = all)")
    p.add_argument("--sleep", type=float, default=0.0,
                   help="seconds to wait between calls")
    p.add_argument("--retries", type=int, default=4,
                   help="attempts per row before giving up")
    p.add_argument("--http-timeout", type=float, default=120.0,
                   help="seconds to wait for each HTTP response")
    p.add_argument("--save-every", type=int, default=25,
                   help="write the workbook every N rows (0 = only at the end)")
    p.add_argument("--resume", action="store_true",
                   help="skip rows that already carry a Malicious verdict")
    p.add_argument("--max-result-chars", type=int, default=12000,
                   help="cap on the query output sent per row")
    p.add_argument("--max-gexf-chars", type=int, default=20000,
                   help="cap on the topology summary")
    p.add_argument("--max-txt-chars", type=int, default=20000,
                   help="cap on the network description")
    p.add_argument("--dry-run", action="store_true",
                   help="build prompts and print the first, but call nothing")
    args = p.parse_args(argv)

    args.skip_prefix = [normalise(s) for s in
                        (args.skip_prefix or list(DEFAULT_SKIP_PREFIXES))]

    for label, path in (("workbook", args.xlsx), ("topology", args.gexf),
                        ("description", args.txt)):
        if not os.path.isfile(path):
            p.error(f"{label} not found: {path}")

    out_dir = args.out
    if os.path.splitext(out_dir)[1].lower() == ".xlsx":
        out_dir = os.path.dirname(out_dir) or "."
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, OUTPUT_FILENAME)

    api_key = "<key>"
    # args.api_key or os.environ.get("GEMINI_API_KEY") \
    #     or os.environ.get("GOOGLE_API_KEY")
    if not api_key and not args.dry_run:
        print("No API key found. Set GEMINI_API_KEY or pass --api-key "
              "(or use --dry-run).", file=sys.stderr)
        return 2

    topology = summarise_gexf(args.gexf, args.max_gexf_chars)
    description = read_text_file(args.txt, args.max_txt_chars)

    print(f"workbook    : {args.xlsx}")
    print(f"topology    : {args.gexf}  ({len(topology)} chars summarised)")
    print(f"description : {args.txt}  ({len(description)} chars)")
    print(f"model       : {args.model}{'  [DRY RUN]' if args.dry_run else ''}")
    print(f"output      : {out_path}\n")

    judge = None if args.dry_run else GeminiJudge(
        api_key, args.model, args.retries, max(args.sleep, 0.5),
        args.http_timeout
    )

    wb = load_workbook(args.xlsx)
    wanted = set(args.sheet) if args.sheet else None
    if wanted:
        missing = wanted - set(wb.sheetnames)
        if missing:
            print(f"no such sheet(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 2

    args._save_callback = lambda: wb.save(out_path)

    totals = {"judged": 0, "skipped": 0, "failed": 0, "resumed": 0,
              "yes": 0, "no": 0}
    try:
        for ws in wb.worksheets:
            if wanted and ws.title not in wanted:
                continue
            for key, val in process_sheet(ws, judge, topology,
                                          description, args).items():
                totals[key] += val
    except KeyboardInterrupt:
        print("\ninterrupted - saving what has been adjudicated so far")
        aborted = True
    except ApiFatal as exc:
        print(f"\nstopping: {exc}", file=sys.stderr)
        print("saving what has been adjudicated so far")
        aborted = True
    else:
        aborted = False
    finally:
        wb.save(out_path)

    print(f"\ndone: {totals['judged']} adjudicated "
          f"({totals['yes']} Yes, {totals['no']} No), "
          f"{totals['skipped']} ignored, {totals['failed']} failed"
          + (f", {totals['resumed']} already done" if totals["resumed"] else ""))
    print(f"saved: {out_path}")
    return 1 if (totals["failed"] or aborted) else 0


if __name__ == "__main__":
    raise SystemExit(main())
