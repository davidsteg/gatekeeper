import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Markdown } from "@/pages/markdown";

describe("Markdown", () => {
  it("renders the RELEASE.md subset as elements", () => {
    const { container } = render(
      <Markdown text={"Intro **bold** and `code`.\n\n### Added\n\n- one\n  - nested\n- two"} />,
    );
    expect(container.querySelector("strong")?.textContent).toBe("bold");
    expect(container.querySelector("code")?.textContent).toBe("code");
    expect(container.querySelector("h4")?.textContent).toBe("Added");
    expect(container.querySelectorAll("ul > li")).toHaveLength(3);
  });

  it("never turns text into markup", () => {
    const { container } = render(<Markdown text={'<img src=x onerror="alert(1)"> **<b>x</b>**'} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror="alert(1)">');
  });
});

describe("Markdown, docs subset", () => {
  it("renders headings, fences, tables, numbered lists and links", () => {
    const { container } = render(
      <Markdown text={[
        "# Title", "", "## Section", "", "```yaml", "a: <b>1</b>", "  - x", "```", "",
        "| A | B |", "|---|---|", "| `x` | y |", "", "1. first", "2. second", "",
        "[site](https://example.com) and [anchor](#x) and [bad](javascript:alert(1))",
      ].join("\n")} />,
    );
    expect(container.querySelector("h2")?.textContent).toBe("Title");
    expect(container.querySelector("h3")?.textContent).toBe("Section");
    expect(container.querySelector("pre")?.textContent).toBe("a: <b>1</b>\n  - x");
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelectorAll("th")).toHaveLength(2);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(1);
    expect(container.querySelectorAll("ol > li")).toHaveLength(2);
    const links = [...container.querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(links).toEqual(["https://example.com", "#x"]);
    expect(container.textContent).toContain("bad");
  });
});

describe("Markdown, prose extras", () => {
  it("renders rules, quotes and italics, and leaves bullets alone", () => {
    const { container } = render(
      <Markdown text={"> In v1: *compiled in*.\n> In v2: data.\n\n---\n\n- a *b* c\n- 2 * 3 = 6"} />,
    );
    expect(container.querySelector("blockquote")?.textContent).toBe("In v1: compiled in. In v2: data.");
    expect(container.querySelector("blockquote em")?.textContent).toBe("compiled in");
    expect(container.querySelector("hr")).not.toBeNull();
    expect(container.querySelectorAll("ul > li")).toHaveLength(2);
    expect(container.querySelectorAll("li em")).toHaveLength(1);
    expect(container.textContent).toContain("2 * 3 = 6");
  });
});
