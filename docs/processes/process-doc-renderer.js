(function () {
  const contentEl = document.getElementById("content");
  const markdownEl = document.getElementById("markdown-content");
  if (!contentEl || !markdownEl || typeof marked === "undefined") {
    return;
  }

  function decodeHtmlEntities(text) {
    const textarea = document.createElement("textarea");
    textarea.innerHTML = String(text || "");
    return textarea.value;
  }

  const markdown = decodeHtmlEntities(markdownEl.textContent || "");
  contentEl.innerHTML = marked.parse(markdown);

  const mermaidCodeBlocks = Array.from(contentEl.querySelectorAll("pre > code")).filter((codeEl) => {
    const className = String(codeEl.className || "");
    return /(^|\s)language-mermaid(\s|$)/.test(className) || /(^|\s)lang-mermaid(\s|$)/.test(className);
  });

  for (const codeEl of mermaidCodeBlocks) {
    const preEl = codeEl.parentElement;
    if (!preEl) {
      continue;
    }
    const mermaidEl = document.createElement("div");
    mermaidEl.className = "mermaid";
    mermaidEl.textContent = codeEl.textContent || "";
    preEl.replaceWith(mermaidEl);
  }

  if (typeof mermaid === "undefined") {
    return;
  }

  mermaid.initialize({
    startOnLoad: false,
    theme: "default",
    securityLevel: "loose",
  });

  const nodes = contentEl.querySelectorAll(".mermaid");
  if (!nodes.length) {
    return;
  }

  if (typeof mermaid.run === "function") {
    mermaid.run({ nodes });
    return;
  }

  if (typeof mermaid.init === "function") {
    mermaid.init(undefined, nodes);
  }
})();
