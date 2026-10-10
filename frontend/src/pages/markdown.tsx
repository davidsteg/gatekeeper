// A deliberately small Markdown renderer for the bundled docs and
// RELEASE.md: headings, bullet and numbered lists (one level of nesting),
// fenced code, pipe tables, rules, > quotes, paragraphs, **bold**, *italic*,
// `code` and [links](url).
// It builds React elements -- never an HTML string -- so it needs no
// innerHTML and stays inside Trusted Types. Anything it does not recognise
// is text.
import { Fragment, type ReactNode } from "react";

// Only web links and in-page anchors become <a>; anything else
// (javascript:, data:, a relative path into the repo) stays as its text.
const SAFE_HREF = /^(https?:\/\/|#)/i;

export function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)\s]+\)|\*[^*\s][^*]*\*)/g;
  let last = 0;
  let key = 0;
  for (const match of text.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > last) out.push(text.slice(last, index));
    const token = match[0];
    if (token.startsWith("**")) {
      out.push(<strong key={key++}>{token.slice(2, -2)}</strong>);
    } else if (token.startsWith("*")) {
      out.push(<em key={key++}>{token.slice(1, -1)}</em>);
    } else if (token.startsWith("`")) {
      out.push(<code key={key++} className="rounded bg-muted px-1 font-mono text-[0.85em]">{token.slice(1, -1)}</code>);
    } else {
      const split = token.indexOf("](");
      const label = token.slice(1, split);
      const href = token.slice(split + 2, -1);
      out.push(
        SAFE_HREF.test(href) ? (
          <a key={key++} href={href} className="text-primary underline" {...(href.startsWith("#") ? {} : { target: "_blank", rel: "noopener noreferrer" })}>
            {label}
          </a>
        ) : (
          <span key={key++}>{label}</span>
        ),
      );
    }
    last = index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const HEADING_CLASS = ["", "mt-4 text-xl font-semibold", "mt-4 text-lg font-semibold", "mt-3 font-semibold", "mt-3 text-sm font-semibold"];

function heading(level: number, content: ReactNode[], key: number) {
  // `#` is the page's own title level below the console's h1.
  const n = Math.min(level, 4);
  const cls = HEADING_CLASS[n];
  if (n === 1) return <h2 key={key} className={cls}>{content}</h2>;
  if (n === 2) return <h3 key={key} className={cls}>{content}</h3>;
  if (n === 3) return <h4 key={key} className={cls}>{content}</h4>;
  return <h5 key={key} className={cls}>{content}</h5>;
}

const cells = (row: string) => row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());

export function Markdown({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  let list: { text: string; nested: string[] }[] = [];
  let ordered = false;
  let para: string[] = [];
  let table: string[] = [];
  let fence: string[] | null = null;
  let quote: string[] = [];
  let key = 0;
  const flushPara = () => {
    if (para.length) blocks.push(<p key={key++}>{inline(para.join(" "))}</p>);
    para = [];
  };
  const flushTable = () => {
    if (table.length) {
      const [head = "", ...rest] = table;
      const body = rest.filter((r) => !/^\s*\|?\s*:?-{2,}/.test(r));
      blocks.push(
        <div key={key++} className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr>{cells(head).map((c, i) => <th key={i} className="border-b border-border px-2 py-1 font-medium">{inline(c)}</th>)}</tr>
            </thead>
            <tbody>
              {body.map((r, i) => (
                <tr key={i}>{cells(r).map((c, j) => <td key={j} className="border-b border-border px-2 py-1 align-top">{inline(c)}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
    }
    table = [];
  };
  const flushList = () => {
    if (list.length) {
      const items = list.map((item, i) => (
        <li key={i}>
          {inline(item.text)}
          {item.nested.length > 0 && (
            <ul className="list-[circle] pl-5">
              {item.nested.map((n, j) => <li key={j}>{inline(n)}</li>)}
            </ul>
          )}
        </li>
      ));
      blocks.push(
        ordered
          ? <ol key={key++} className="list-decimal space-y-1 pl-5">{items}</ol>
          : <ul key={key++} className="list-disc space-y-1 pl-5">{items}</ul>,
      );
    }
    list = [];
  };
  const flushQuote = () => {
    if (quote.length) {
      blocks.push(
        <blockquote key={key++} className="border-l-2 border-border pl-3 text-muted-foreground">
          {inline(quote.join(" "))}
        </blockquote>,
      );
    }
    quote = [];
  };
  const flushAll = () => { flushPara(); flushList(); flushTable(); flushQuote(); };
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    if (fence !== null) {
      if (/^\s*```/.test(line)) {
        blocks.push(
          <pre key={key++} className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-snug">{fence.join("\n")}</pre>,
        );
        fence = null;
      } else {
        fence.push(raw);
      }
      continue;
    }
    const head = /^(#{1,6})\s+(.*)$/.exec(line);
    const bullet = /^(\s*)[-*]\s+(.*)$/.exec(line);
    const numbered = /^(\s*)\d+[.)]\s+(.*)$/.exec(line);
    if (/^\s*```/.test(line)) {
      flushAll();
      fence = [];
    } else if (!line.trim()) {
      flushAll();
    } else if (/^\s*(---+|\*\*\*+)\s*$/.test(line)) {
      flushAll();
      blocks.push(<hr key={key++} className="border-border" />);
    } else if (/^\s*>/.test(line)) {
      flushPara();
      flushList();
      flushTable();
      quote.push(line.replace(/^\s*>\s?/, ""));
    } else if (/^\s*\|/.test(line)) {
      flushPara();
      flushList();
      table.push(line);
    } else if (head) {
      flushAll();
      blocks.push(heading((head[1] ?? "").length, inline(head[2] ?? ""), key++));
    } else if (bullet || numbered) {
      flushPara();
      flushTable();
      const match = (bullet ?? numbered) as RegExpExecArray;
      const content = match[2] ?? "";
      const nested = (match[1] ?? "").length >= 2 && list.length > 0;
      if (nested) {
        list.at(-1)?.nested.push(content);
      } else {
        if (list.length && ordered !== Boolean(numbered)) flushList();
        if (!list.length) ordered = Boolean(numbered);
        list.push({ text: content, nested: [] });
      }
    } else if (list.length && /^\s+\S/.test(raw)) {
      const item = list.at(-1);
      if (item) {
        if (item.nested.length) item.nested[item.nested.length - 1] += ` ${line.trim()}`;
        else item.text += ` ${line.trim()}`;
      }
    } else {
      flushList();
      flushTable();
      para.push(line.trim());
    }
  }
  if (fence !== null) blocks.push(<pre key={key++} className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{fence.join("\n")}</pre>);
  flushAll();
  return <div className="space-y-2 text-sm leading-relaxed">{blocks.map((b, i) => <Fragment key={i}>{b}</Fragment>)}</div>;
}
