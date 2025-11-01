#!/usr/bin/env python3
"""
Convert Dilithion Markdown Documentation to HTML (for PDF printing)
"""

import re
import sys

def markdown_to_html(md_file, html_file):
    """Convert markdown to HTML with styling for PDF export"""

    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # HTML template with CSS for technical PDF output
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dilithion - Comprehensive Technical Documentation</title>
    <style>
        @page {
            size: A4;
            margin: 1.5cm;
        }

        body {
            font-family: 'Times New Roman', Times, serif;
            line-height: 1.3;
            color: #000;
            max-width: 100%;
            margin: 0;
            padding: 10pt 10pt 10pt 15pt;
            font-size: 10pt;
        }

        h1 {
            color: #000;
            border-bottom: 1px solid #000;
            padding-bottom: 3px;
            margin-top: 12pt;
            margin-bottom: 8pt;
            page-break-before: always;
            font-size: 16pt;
            font-weight: bold;
        }

        h1:first-of-type {
            page-break-before: avoid;
            font-size: 18pt;
        }

        h2 {
            color: #000;
            border-bottom: 1px solid #666;
            padding-bottom: 2px;
            margin-top: 10pt;
            margin-bottom: 6pt;
            font-size: 13pt;
            font-weight: bold;
        }

        h3 {
            color: #000;
            margin-top: 8pt;
            margin-bottom: 4pt;
            font-size: 11pt;
            font-weight: bold;
        }

        h4 {
            color: #000;
            margin-top: 6pt;
            margin-bottom: 3pt;
            font-size: 10pt;
            font-weight: bold;
        }

        p {
            margin: 4pt 0;
        }

        code {
            background-color: #f0f0f0;
            padding: 1px 3px;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
        }

        pre {
            background-color: #f5f5f5;
            border: 1px solid #ccc;
            color: #000;
            padding: 6pt;
            overflow-x: auto;
            page-break-inside: avoid;
            font-size: 8pt;
            line-height: 1.2;
            margin: 6pt 0;
        }

        pre code {
            background-color: transparent;
            color: #000;
            padding: 0;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin: 6pt 0;
            page-break-inside: avoid;
            font-size: 9pt;
        }

        th, td {
            border: 1px solid #666;
            padding: 4pt 6pt;
            text-align: left;
        }

        th {
            background-color: #d0d0d0;
            color: #000;
            font-weight: bold;
        }

        tr:nth-child(even) {
            background-color: #f8f8f8;
        }

        blockquote {
            border-left: 2px solid #666;
            padding-left: 10px;
            margin: 6pt 0 6pt 10pt;
            font-style: italic;
            color: #333;
        }

        ul, ol {
            margin: 4pt 0;
            padding-left: 20pt;
        }

        li {
            margin: 2pt 0;
        }

        a {
            color: #000;
            text-decoration: underline;
        }

        .checkmark {
            color: #000;
            font-weight: normal;
        }

        .crossmark {
            color: #000;
            font-weight: normal;
        }

        .warning {
            color: #000;
            font-weight: normal;
        }

        hr {
            border: none;
            border-top: 1px solid #999;
            margin: 8pt 0;
        }

        strong {
            font-weight: bold;
        }

        em {
            font-style: italic;
        }

        @media print {
            body {
                max-width: 100%;
            }

            a {
                color: #000;
            }

            pre {
                page-break-inside: avoid;
            }

            table {
                page-break-inside: avoid;
            }

            h1, h2, h3, h4 {
                page-break-after: avoid;
            }
        }
    </style>
</head>
<body>
{CONTENT}
</body>
</html>"""

    # Basic markdown conversion
    html_content = content

    # Headers
    html_content = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^#### (.+)$', r'<h4>\1</h4>', html_content, flags=re.MULTILINE)

    # Bold and italic
    html_content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_content)
    html_content = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html_content)

    # Code blocks
    html_content = re.sub(r'```([^\n]*)\n(.*?)```', r'<pre><code>\2</code></pre>', html_content, flags=re.DOTALL)

    # Inline code
    html_content = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_content)

    # Links
    html_content = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', r'<a href="\2">\1</a>', html_content)

    # Horizontal rules
    html_content = re.sub(r'^---$', r'<hr>', html_content, flags=re.MULTILINE)

    # Lists - unordered
    html_content = re.sub(r'^\- (.+)$', r'<li>\1</li>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'((?:<li>.*</li>\n)+)', r'<ul>\n\1</ul>\n', html_content)

    # Checkmarks and symbols
    html_content = html_content.replace('✅', '<span class="checkmark">✅</span>')
    html_content = html_content.replace('❌', '<span class="crossmark">❌</span>')
    html_content = html_content.replace('⚠️', '<span class="warning">⚠️</span>')
    html_content = html_content.replace('⏳', '<span class="warning">⏳</span>')

    # Tables (simple conversion)
    lines = html_content.split('\n')
    new_lines = []
    in_table = False

    for i, line in enumerate(lines):
        if '|' in line and i > 0:
            if not in_table:
                new_lines.append('<table>')
                in_table = True

            cells = [cell.strip() for cell in line.split('|')[1:-1]]

            # Check if it's a header separator line
            if all(re.match(r'^-+$', cell) for cell in cells):
                continue

            # Check if previous line suggests this is a header
            is_header = i > 0 and '|' in lines[i-1] and i < len(lines) - 1 and '|' in lines[i+1] and all(re.match(r'^-+$', cell.strip()) for cell in lines[i+1].split('|')[1:-1])

            if is_header or (in_table and i == 1):
                new_lines.append('<tr>')
                for cell in cells:
                    new_lines.append(f'<th>{cell}</th>')
                new_lines.append('</tr>')
            else:
                new_lines.append('<tr>')
                for cell in cells:
                    new_lines.append(f'<td>{cell}</td>')
                new_lines.append('</tr>')
        else:
            if in_table:
                new_lines.append('</table>')
                in_table = False
            new_lines.append(line)

    if in_table:
        new_lines.append('</table>')

    html_content = '\n'.join(new_lines)

    # Paragraphs
    html_content = re.sub(r'\n\n+', '</p>\n<p>', html_content)
    html_content = '<p>' + html_content + '</p>'

    # Clean up
    html_content = html_content.replace('<p></p>', '')
    html_content = html_content.replace('<p><h', '<h')
    html_content = html_content.replace('</h1></p>', '</h1>')
    html_content = html_content.replace('</h2></p>', '</h2>')
    html_content = html_content.replace('</h3></p>', '</h3>')
    html_content = html_content.replace('</h4></p>', '</h4>')
    html_content = html_content.replace('<p><ul>', '<ul>')
    html_content = html_content.replace('</ul></p>', '</ul>')
    html_content = html_content.replace('<p><table>', '<table>')
    html_content = html_content.replace('</table></p>', '</table>')
    html_content = html_content.replace('<p><pre>', '<pre>')
    html_content = html_content.replace('</pre></p>', '</pre>')
    html_content = html_content.replace('<p><hr></p>', '<hr>')

    # Insert into template
    html = html_template.replace('{CONTENT}', html_content)

    # Write HTML file
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[OK] HTML created: {html_file}")
    print(f"")
    print(f"[INFO] To create PDF:")
    print(f"   1. Open {html_file} in your browser")
    print(f"   2. Press Ctrl+P (or Cmd+P on Mac)")
    print(f"   3. Select 'Save as PDF' or 'Microsoft Print to PDF'")
    print(f"   4. Save as: DILITHION-COMPREHENSIVE-TECHNICAL-DOCUMENTATION.pdf")

if __name__ == '__main__':
    md_file = 'DILITHION-COMPREHENSIVE-TECHNICAL-DOCUMENTATION.md'
    html_file = 'DILITHION-COMPREHENSIVE-TECHNICAL-DOCUMENTATION.html'

    try:
        markdown_to_html(md_file, html_file)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {md_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
