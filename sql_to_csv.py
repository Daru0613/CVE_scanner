"""Convert the compact SQL row export used by the sample data to CSV."""

import argparse
import csv
import re
from pathlib import Path


def split_sql_row(row: str) -> list[str]:
    values = []
    value = []
    quoted = False
    index = 0
    while index < len(row):
        char = row[index]
        if quoted:
            if char == "\\" and index + 1 < len(row):
                value.append(row[index + 1])
                index += 2
                continue
            if char == "'":
                if index + 1 < len(row) and row[index + 1] == "'":
                    value.append("'")
                    index += 2
                    continue
                quoted = False
            else:
                value.append(char)
        elif char == "'":
            quoted = True
        elif char == ",":
            values.append("".join(value).strip())
            value = []
        else:
            value.append(char)
        index += 1
    if quoted:
        raise ValueError("unterminated SQL string")
    values.append("".join(value).strip())
    return ["" if value.upper() == "NULL" else value for value in values]


def extract_sql_rows(text: str) -> list[str]:
    rows = []
    start = None
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and quoted:
            index += 2
            continue
        if char == "'":
            if quoted and index + 1 < len(text) and text[index + 1] == "'":
                index += 2
                continue
            quoted = not quoted
        elif not quoted and char == "(" and start is None:
            start = index + 1
        elif not quoted and char == ")" and start is not None:
            rows.append(text[start:index])
            start = None
        index += 1
    if quoted or start is not None:
        raise ValueError("unterminated SQL row")
    return rows


def convert(source: Path, destination: Path, encoding: str) -> None:
    text = source.read_text(encoding=encoding).strip()
    schema_definition = re.compile(
        r"(?:^|[,;])\s*`?[a-z_][a-z0-9_]*`?\s+"
        r"(?:tinyint|smallint|mediumint|int|bigint|varchar|char|text|longtext|datetime|timestamp|set)\b",
        re.IGNORECASE,
    )
    if schema_definition.search(text) and not re.search(r"\b(?:INSERT\s+INTO|VALUES)\b", text, re.IGNORECASE):
        raise ValueError("SQL schema only; no row values found, so CSV cannot be created")
    first_row = text.find("(")
    if first_row < 0:
        raise ValueError("expected whitespace-separated header followed by SQL rows")
    header = text[:first_row].split()
    row_text = text[first_row:]
    rows = []
    for row_text in extract_sql_rows(row_text):
        row = split_sql_row(row_text)
        if len(row) != len(header):
            raise ValueError(f"row has {len(row)} values; expected {len(header)}")
        rows.append(row)
    if not rows:
        raise ValueError("no SQL rows found")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--encoding", default="utf-8")
    arguments = parser.parse_args()
    convert(arguments.source, arguments.destination, arguments.encoding)
    print(f"converted {arguments.source} -> {arguments.destination}")


if __name__ == "__main__":
    main()
