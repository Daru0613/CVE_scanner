"""CSV input, including pasted CSV whose quoted row boundaries became spaces."""

import csv
import io


def restore_row_breaks(text: str) -> str:
    output = []
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        output.append(char)
        if char == '"':
            if quoted and index + 1 < len(text) and text[index + 1] == '"':
                output.append('"')
                index += 2
                continue
            quoted = not quoted
            if not quoted:
                end = index + 1
                while end < len(text) and text[end] in ' \t':
                    end += 1
                if end > index + 1 and end < len(text) and text[end] == '"':
                    output.append('\n')
                    index = end
                    continue
        index += 1
    return ''.join(output)


def parse_csv(text: str) -> list[dict[str, str]]:
    try:
        records = [row for row in csv.reader(io.StringIO(text, newline=''), strict=True) if row]
    except csv.Error:
        raise ValueError('CSV quoting is invalid; export the original CSV with row breaks') from None
    if not records:
        raise ValueError('CSV is empty')
    header = [name.strip() for name in records[0]]
    if len(header) < 2 or any(not name for name in header) or len(set(header)) != len(header):
        raise ValueError('CSV requires at least two distinct, nonempty column names')
    if len(records) < 2:
        raise ValueError('CSV contains a header but no data records')
    rows = []
    for number, record in enumerate(records[1:], 2):
        if len(record) != len(header):
            raise ValueError(f'CSV record {number}: expected {len(header)} columns, found {len(record)}')
        rows.append(dict(zip(header, record)))
    return rows


def rows_from_csv(text: str) -> list[dict[str, str]]:
    try:
        return parse_csv(text)
    except ValueError:
        # Only attempt recovery for a single physical line. Never guess row sizes
        # or pad/drop columns; restored rows must exactly match the header.
        if '\n' in text.strip() or '\r' in text.strip():
            raise
        restored = restore_row_breaks(text)
        if restored == text:
            raise
        return parse_csv(restored)
