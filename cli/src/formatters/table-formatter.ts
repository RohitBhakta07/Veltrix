/**
 * VELTRIX CLI — Terminal Table Formatter
 * Generates clean text tables with column width calculation and ANSI injection protection.
 */

/**
 * Strips ANSI control characters, escape sequences, and carriage returns to prevent terminal spoofing.
 */
export function sanitizeTerminalText(input: string | number | boolean | null | undefined): string {
  if (input === null || input === undefined) return '';
  const str = String(input);
  // Strip ANSI escape codes (\x1b[...] or \u001b[...]) and raw control codes except newline/tab
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/\r/g, '');
}

export interface TableColumn<T> {
  header: string;
  key?: keyof T;
  width?: number;
  format?: (row: T) => string;
}

export function formatTable<T extends Record<string, any>>(rows: T[], columns?: TableColumn<T>[]): string {
  if (!rows || rows.length === 0) {
    return 'No records found.';
  }

  const cols: TableColumn<T>[] =
    columns && columns.length > 0
      ? columns
      : Object.keys(rows[0] || {}).map((k) => ({
          header: k,
          key: k as keyof T,
        }));

  // Calculate maximum column widths
  const widths: number[] = cols.map((col) => {
    let max = col.header.length;
    for (const row of rows) {
      let val = '';
      if (col.format) {
        val = col.format(row);
      } else if (col.key && row[col.key] !== undefined) {
        val = String(row[col.key]);
      }
      const len = sanitizeTerminalText(val).length;
      if (len > max) max = len;
    }
    // Cap column width to prevent overflow
    return Math.min(Math.max(max, col.width || 0), 45);
  });

  // Render header
  const headerLine = cols
    .map((col, idx) => {
      const w = widths[idx]!;
      return sanitizeTerminalText(col.header).padEnd(w);
    })
    .join('  ');

  // Render divider
  const dividerLine = widths.map((w) => '-'.repeat(w)).join('  ');

  // Render rows
  const rowLines = rows.map((row) => {
    return cols
      .map((col, idx) => {
        const w = widths[idx]!;
        let val = '';
        if (col.format) {
          val = col.format(row);
        } else if (col.key && row[col.key] !== undefined) {
          val = String(row[col.key]);
        }
        return sanitizeTerminalText(val).padEnd(w);
      })
      .join('  ');
  });

  return [headerLine, dividerLine, ...rowLines].join('\n');
}

export function formatKeyValue(pairs: Record<string, unknown>): string {
  const entries = Object.entries(pairs).filter(([_, val]) => val !== undefined);
  if (entries.length === 0) return '';

  const maxKeyLen = Math.max(...entries.map(([k]) => k.length));
  return entries
    .map(([k, v]) => {
      const formattedKey = sanitizeTerminalText(k).padEnd(maxKeyLen);
      let formattedVal = '';
      if (typeof v === 'object' && v !== null) {
        formattedVal = JSON.stringify(v);
      } else {
        formattedVal = sanitizeTerminalText(String(v));
      }
      return `  ${formattedKey} : ${formattedVal}`;
    })
    .join('\n');
}
