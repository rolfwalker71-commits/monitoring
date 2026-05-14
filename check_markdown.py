import html
import re

html_path = 'docs/processes/datenholung-prozess.html'
with open(html_path, 'r', encoding='utf-8') as f:
    content = f.read()

match = re.search(r'<script id="markdown-content" type="text/markdown">(.*?)</script>', content, re.DOTALL)
if match:
    markdown = match.group(1).strip()
    lines = markdown.splitlines()
    target_lines = [line for line in lines if '--&gt;' in line]
    
    print("Found escaped lines:")
    for line in target_lines[:2]:
        print(line)
        
    print("\nUnescaped lines:")
    for line in target_lines[:2]:
        print(html.unescape(line))
else:
    print("Markdown script not found.")

js_path = 'docs/processes/process-doc-renderer.js'
with open(js_path, 'r', encoding='utf-8') as f:
    js_content = f.read()
    if 'decode' in js_content.lower() or 'unescape' in js_content.lower() or 'innerhtml' in js_content.lower():
        print("\nRenderer check: The JS file contains potential decoding/content handling logic.")
    else:
        print("\nRenderer check: No obvious decoding logic found in JS.")
