#!/usr/bin/env python3
"""
Converts Notion HTML exports in notas/ to clean Markdown in notas-md/.
- Strips Notion UUIDs from filenames
- Preserves directory structure and images
- Pre-processes HTML to remove Notion wrapper divs before pandoc conversion
- Post-processes to clean up any remaining HTML artifacts
"""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from bs4 import BeautifulSoup

SRC = Path("/home/sebastian/Documentos/inventario-tecnicas-ciberseguridad/notas")
DST = Path("/home/sebastian/Documentos/inventario-tecnicas-ciberseguridad/notas-md")

UUID_PATTERN = re.compile(r'\s+[0-9a-f]{20,}$', re.IGNORECASE)


def clean_name(name: str) -> str:
    stem = Path(name).stem
    ext = Path(name).suffix
    cleaned = UUID_PATTERN.sub('', stem)
    return cleaned + ext


def clean_path(rel_path: Path) -> Path:
    parts = []
    for part in rel_path.parts:
        parts.append(clean_name(part))
    return Path(*parts)


def preprocess_html(html_path: Path) -> str:
    """
    Pre-process Notion HTML to make it cleaner for pandoc:
    - Remove wrapper divs with display:contents
    - Unwrap figure elements to just img tags
    - Remove script/link tags (prism.js)
    - Remove empty spans
    """
    with open(html_path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')

    # Remove all <script> and <link> tags
    for tag in soup.find_all(['script', 'link']):
        tag.decompose()

    # Remove <style> tags
    for tag in soup.find_all('style'):
        tag.decompose()

    # Unwrap divs with display:contents (Notion wrapper divs)
    for div in soup.find_all('div', style=re.compile(r'display:\s*contents')):
        div.unwrap()

    # Unwrap the page-body div
    for div in soup.find_all('div', class_='page-body'):
        div.unwrap()

    # Clean up figure tags - convert to just the img
    for figure in soup.find_all('figure'):
        img = figure.find('img')
        if img:
            # Remove the wrapping <a> if present
            a_tag = figure.find('a')
            if a_tag and img:
                # Keep just the img
                figure.replace_with(img)
            else:
                figure.replace_with(img)

    # Remove empty spans
    for span in soup.find_all('span'):
        if not span.get_text(strip=True):
            span.decompose()

    # Remove style attributes from img (width etc are lost in md anyway)
    for img in soup.find_all('img'):
        if img.get('style'):
            del img['style']

    # Remove id attributes from elements (Notion IDs)
    for tag in soup.find_all(True):
        if tag.get('id'):
            del tag['id']
        if tag.get('class'):
            # Keep 'code' class for code blocks, remove others
            classes = tag.get('class', [])
            if 'code' in classes or 'code-wrap' in classes:
                pass  # keep
            else:
                del tag['class']

    return str(soup)


def postprocess_md(md_content: str) -> str:
    """Clean up the markdown output."""
    # Remove leftover HTML div tags
    md_content = re.sub(r'<div[^>]*>\s*', '', md_content)
    md_content = re.sub(r'\s*</div>', '', md_content)

    # Remove leftover span tags
    md_content = re.sub(r'<span[^>]*>\s*</span>', '', md_content)
    md_content = re.sub(r'<span[^>]*>', '', md_content)
    md_content = re.sub(r'</span>', '', md_content)

    # Remove leftover article tags
    md_content = re.sub(r'<article[^>]*>', '', md_content)
    md_content = re.sub(r'</article>', '', md_content)

    # Remove leftover header tags
    md_content = re.sub(r'<header>', '', md_content)
    md_content = re.sub(r'</header>', '', md_content)

    # Remove leftover figure/figcaption tags
    md_content = re.sub(r'<figure[^>]*>', '', md_content)
    md_content = re.sub(r'</figure>', '', md_content)
    md_content = re.sub(r'<figcaption[^>]*>.*?</figcaption>', '', md_content)

    # Fix code blocks: ``` code -> ```
    md_content = re.sub(r'```\s*code\b', '```', md_content)

    # Clean up excessive blank lines
    md_content = re.sub(r'\n{3,}', '\n\n', md_content)

    # Strip leading/trailing whitespace
    md_content = md_content.strip() + '\n'

    return md_content


def convert_html_to_md(html_path: Path, md_path: Path, img_mapping: dict):
    """Convert an HTML file to Markdown."""
    md_path.parent.mkdir(parents=True, exist_ok=True)

    # Pre-process the HTML
    cleaned_html = preprocess_html(html_path)

    # Write to temp file for pandoc
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as tmp:
        tmp.write(cleaned_html)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "pandoc",
                tmp_path,
                "-f", "html-native_divs-native_spans",
                "-t", "gfm",
                "--wrap=none",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(tmp_path)

    if result.returncode != 0:
        print(f"  ERROR converting {html_path}: {result.stderr}")
        return False

    md_content = result.stdout

    # Fix image references
    for old_ref, new_ref in img_mapping.items():
        md_content = md_content.replace(old_ref, new_ref)

    # Post-process
    md_content = postprocess_md(md_content)

    md_path.write_text(md_content, encoding='utf-8')
    return True


def main():
    # Remove old output
    if DST.exists():
        shutil.rmtree(DST)

    html_files = []
    image_files = []

    for root, dirs, files in os.walk(SRC):
        root_path = Path(root)
        for f in files:
            full = root_path / f
            rel = full.relative_to(SRC)
            if f.lower().endswith('.html'):
                html_files.append(rel)
            elif f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')):
                image_files.append(rel)

    print(f"Found {len(html_files)} HTML files and {len(image_files)} images")

    # Copy images
    for img_rel in image_files:
        new_rel = clean_path(img_rel)
        dst_img = DST / new_rel
        dst_img.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SRC / img_rel, dst_img)

    print(f"Copied {len(image_files)} images")

    # Convert HTML files
    converted = 0
    errors = 0
    for html_rel in html_files:
        new_rel = clean_path(html_rel).with_suffix('.md')
        dst_md = DST / new_rel

        # Build image mapping relative to this HTML file
        html_dir = html_rel.parent
        new_dir = clean_path(html_rel).parent
        local_img_mapping = {}

        for img_rel in image_files:
            try:
                old_img_relative = (SRC / img_rel).relative_to(SRC / html_dir)
                new_img_relative = (DST / clean_path(img_rel)).relative_to(DST / new_dir)
                old_str = str(old_img_relative)
                new_str = str(new_img_relative)
                local_img_mapping[old_str] = new_str
                local_img_mapping[old_str.replace(' ', '%20')] = new_str
            except ValueError:
                continue

        if convert_html_to_md(SRC / html_rel, dst_md, local_img_mapping):
            converted += 1
        else:
            errors += 1

    print(f"\nDone! Converted {converted} files, {errors} errors")
    print(f"Output directory: {DST}")


if __name__ == "__main__":
    main()
