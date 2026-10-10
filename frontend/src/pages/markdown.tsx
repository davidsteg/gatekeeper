// A deliberately tiny Markdown renderer for RELEASE.md: headings, bullet
// lists (one level of nesting), paragraphs, **bold** and `code`. It builds
// React elements -- never an HTML string -- so it needs no innerHTML and
// stays inside Trusted Types. Anything it does not recognise is text.
import { Fragment, type ReactNode } from "react";

export function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let key = 0;
  for (const match of text.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > last) out.push(text.slice(last, index));
    const token = match[0];
    out.push(
      token.startsWith("**")
        ? <strong key={key++}>{token.slice(2, -2)}</strong>
        : <code key={key++} className="rounded bg-muted px-1 font-mono text-[0.85em]">{token.slice(1, -1)}</code>,
    );
    last = index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Markdown({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  let list: { text: string; nested: string[] }[] = [];
  let para: string[] = [];
  let key = 0;
  const flushPara = () => {
    if (para.length) blocks.push(<p key={key++}>{inline(para.join(" "))}</p>);
    para = [];
  };
  const flushList = () => {
    if (list.length) {
      blocks.push(
        <ul key={key++} className="list-disc space-y-1 pl-5">
          {list.map((item, i) => (
            <li key={i}>
              {inline(item.text)}
              {item.nested.length > 0 && (
                <ul className="list-[circle] pl-5">
                  {item.nested.map((n, j) => <li key={j}>{inline(n)}</li>)}
                </ul>
              )}
            </li>
          ))}
        </ul>,
      );
    }
    list = [];
  };
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    const heading = /^(#{3,6})\s+(.*)$/.exec(line);
    const bullet = /^(\s*)[-*]\s+(.*)$/.exec(line);
    if (!line.trim()) {
      flushPara();
      flushList();
    } else if (heading) {
      flushPara();
      flushList();
      blocks.push(<h4 key={key++} className="mt-3 font-semibold">{inline(heading[2] ?? "")}</h4>);
    } else if (bullet) {
      flushPara();
      const content = bullet[2] ?? "";
      if ((bullet[1] ?? "").length >= 2 && list.length) list.at(-1)?.nested.push(content);
      else list.push({ text: content, nested: [] });
    } else if (list.length && /^\s+\S/.test(raw)) {
      const item = list.at(-1);
      if (item) {
        if (item.nested.length) item.nested[item.nested.length - 1] += ` ${line.trim()}`;
        else item.text += ` ${line.trim()}`;
      }
    } else {
      flushList();
      para.push(line.trim());
    }
  }
  flushPara();
  flushList();
  return <div className="space-y-2 text-sm leading-relaxed">{blocks.map((b, i) => <Fragment key={i}>{b}</Fragment>)}</div>;
}
