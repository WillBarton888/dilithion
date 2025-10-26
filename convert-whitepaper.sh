#!/bin/bash
# Simple Markdown to HTML converter for whitepaper

input="WHITEPAPER.md"
output="WHITEPAPER.html"

cat > "$output" << 'HTML_START'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dilithion: A Post-Quantum Cryptocurrency - Whitepaper v1.0</title>
    <style>
        @page {
            size: letter;
            margin: 1in;
        }
        body {
            font-family: 'Georgia', 'Times New Roman', serif;
            line-height: 1.6;
            color: #333;
            max-width: 8.5in;
            margin: 0 auto;
            padding: 20px;
            font-size: 11pt;
        }
        h1 {
            color: #1a1a1a;
            font-size: 24pt;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
            page-break-after: avoid;
        }
        h2 {
            color: #2c3e50;
            font-size: 18pt;
            margin-top: 25px;
            margin-bottom: 12px;
            page-break-after: avoid;
        }
        h3 {
            color: #34495e;
            font-size: 14pt;
            margin-top: 20px;
            margin-bottom: 10px;
            page-break-after: avoid;
        }
        p {
            margin: 10px 0;
            text-align: justify;
        }
        ul, ol {
            margin: 10px 0;
            padding-left: 30px;
        }
        li {
            margin: 5px 0;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 10pt;
        }
        pre {
            background: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            line-height: 1.4;
            page-break-inside: avoid;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 15px 0;
            page-break-inside: avoid;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            page-break-inside: avoid;
        }
        .title-page {
            text-align: center;
            page-break-after: always;
            padding-top: 200px;
        }
        .title-page h1 {
            font-size: 32pt;
            border: none;
            margin-bottom: 20px;
        }
        .title-page p {
            font-size: 14pt;
            margin: 10px 0;
        }
        @media print {
            body {
                font-size: 10pt;
            }
            a {
                color: #000;
                text-decoration: none;
            }
        }
    </style>
</head>
<body>
HTML_START

# Convert markdown to HTML (simple conversion)
sed '
# Title page
1s|^# \(.*\)|<div class="title-page"><h1>\1</h1>|
2s|^\*\*Version \(.*\)\*\*|<p><strong>Version \1</strong></p>|
3s|^\*\*\(.*\)\*\*|<p><strong>\1</strong></p>|
5s|^\*\*Launch Date:\*\* \(.*\)|<p><strong>Launch Date:</strong> \1</p></div>|

# Headings
s|^## \(.*\)|<h2>\1</h2>|
s|^### \(.*\)|<h3>\1</h3>|

# Bold
s|\*\*\([^*]*\)\*\*|<strong>\1</strong>|g

# Lists
s|^- |<li>|
s|^[0-9]\+\. |<li>|

# Code blocks (simple)
s|^```|<pre><code>|
s|```$|</code></pre>|

# Inline code
s|`\([^`]*\)`|<code>\1</code>|g

# Horizontal rules
s|^---$|<hr>|

# Paragraphs (lines that are not empty and not special)
/^[^<]/ s|^\(.*\)|<p>\1</p>|
' "$input" >> "$output"

cat >> "$output" << 'HTML_END'
</body>
</html>
HTML_END

echo "Converted $input to $output"
