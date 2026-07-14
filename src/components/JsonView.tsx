import { useState } from "preact/hooks";
import type { JSX } from "preact";

/**
 * Syntax-highlighted JSON built from JSX nodes, never from an HTML string.
 *
 * S5 is explicit that a claim value containing `<script>` must render as text.
 * The only way to guarantee that is to never construct markup from the data —
 * so there is no innerHTML / dangerouslySetInnerHTML anywhere in this file, and
 * there must never be. Preact escapes text children by construction.
 */

/** Beyond this, a node renders collapsed so a 10k-key payload can't jank the page. */
const AUTO_COLLAPSE_ENTRIES = 25;
const AUTO_COLLAPSE_DEPTH = 3;

interface NodeProps {
  value: unknown;
  depth: number;
}

function Punct({ children }: { children: string }): JSX.Element {
  return <span class="tok-punct">{children}</span>;
}

function Scalar({ value }: { value: unknown }): JSX.Element {
  if (value === null) return <span class="tok-null">null</span>;

  switch (typeof value) {
    case "string":
      return <span class="tok-string">{JSON.stringify(value)}</span>;
    case "number":
      return <span class="tok-number">{String(value)}</span>;
    case "boolean":
      return <span class="tok-bool">{String(value)}</span>;
    default:
      return <span class="tok-string">{JSON.stringify(value) ?? "undefined"}</span>;
  }
}

function Node({ value, depth }: NodeProps): JSX.Element {
  const isObject = typeof value === "object" && value !== null;
  const entries: [string, unknown][] = !isObject
    ? []
    : Array.isArray(value)
      ? value.map((item, index) => [String(index), item])
      : Object.entries(value as Record<string, unknown>);

  const shouldCollapse =
    isObject &&
    (entries.length > AUTO_COLLAPSE_ENTRIES || depth >= AUTO_COLLAPSE_DEPTH) &&
    entries.length > 0;

  const [open, setOpen] = useState(!shouldCollapse);

  if (!isObject) return <Scalar value={value} />;

  const isArray = Array.isArray(value);
  const [openBrace, closeBrace] = isArray ? ["[", "]"] : ["{", "}"];

  if (entries.length === 0) {
    return <Punct>{openBrace + closeBrace}</Punct>;
  }

  if (!open) {
    return (
      <span>
        <Punct>{openBrace}</Punct>
        <button
          type="button"
          class="json-toggle"
          onClick={() => setOpen(true)}
          aria-label={`Expand ${entries.length} entries`}
        >
          … {entries.length} {entries.length === 1 ? "entry" : "entries"}
        </button>
        <Punct>{closeBrace}</Punct>
      </span>
    );
  }

  const indent = "  ".repeat(depth + 1);
  const closeIndent = "  ".repeat(depth);

  return (
    <span>
      <Punct>{openBrace}</Punct>
      {shouldCollapse && (
        <button
          type="button"
          class="json-toggle"
          onClick={() => setOpen(false)}
          aria-label="Collapse"
        >
          −
        </button>
      )}
      {"\n"}
      {entries.map(([key, child], index) => (
        <span key={key}>
          {indent}
          {!isArray && (
            <>
              <span class="tok-key">{JSON.stringify(key)}</span>
              <Punct>: </Punct>
            </>
          )}
          <Node value={child} depth={depth + 1} />
          {index < entries.length - 1 && <Punct>,</Punct>}
          {"\n"}
        </span>
      ))}
      {closeIndent}
      <Punct>{closeBrace}</Punct>
    </span>
  );
}

export function JsonView({ value }: { value: unknown }): JSX.Element {
  return (
    <pre class="code">
      <Node value={value} depth={0} />
    </pre>
  );
}
