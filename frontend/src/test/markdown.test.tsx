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
