# How to Generate Dilithion Whitepaper PDF

**Source:** WHITEPAPER.md
**Target:** Professional PDF for distribution

---

## Quick Options (Recommended)

### Option 1: Pandoc (Best Quality) ⭐

**Install Pandoc:**
```bash
# Windows (with chocolatey)
choco install pandoc

# Or download from: https://pandoc.org/installing.html
```

**Generate PDF:**
```bash
cd C:\Users\will\dilithion

pandoc WHITEPAPER.md -o WHITEPAPER.pdf \
  --pdf-engine=xelatex \
  --toc \
  --toc-depth=2 \
  --number-sections \
  --highlight-style=tango \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  -V documentclass=article \
  -V papersize=letter
```

**Result:** Professional-quality PDF with table of contents, numbered sections, proper formatting.

---

### Option 2: Typora (Easiest)

**Install Typora:** https://typora.io/ (WYSIWYG Markdown editor)

**Steps:**
1. Open WHITEPAPER.md in Typora
2. File → Export → PDF
3. Choose settings (include TOC, page numbers)
4. Export

**Result:** Clean, well-formatted PDF with minimal effort.

---

### Option 3: VS Code + Extension

**Install:**
1. Open VS Code
2. Install extension: "Markdown PDF" by yzane
3. Open WHITEPAPER.md
4. Right-click → "Markdown PDF: Export (pdf)"

**Result:** Quick PDF generation, decent quality.

---

### Option 4: Online Converter

**Websites:**
- https://www.markdowntopdf.com/
- https://cloudconvert.com/md-to-pdf
- https://www.converter.app/md-to-pdf/

**Steps:**
1. Upload WHITEPAPER.md
2. Convert
3. Download PDF

**Note:** Check privacy policy before uploading sensitive documents.

---

## Professional Formatting Tips

### Custom Cover Page

Add to beginning of WHITEPAPER.md:

```markdown
---
title: "Dilithion: A Post-Quantum Cryptocurrency"
subtitle: "Technical Whitepaper Version 1.0"
author: "Dilithion Core Developers"
date: "October 2025"
abstract: |
  Dilithion is a decentralized cryptocurrency designed from the ground up
  for the post-quantum era, implementing CRYSTALS-Dilithium signatures
  and RandomX proof-of-work.
---

\newpage
```

### Page Numbers & Headers (Pandoc)

```bash
pandoc WHITEPAPER.md -o WHITEPAPER.pdf \
  --pdf-engine=xelatex \
  --toc \
  --number-sections \
  -V geometry:margin=1in \
  -V pagestyle=headings \
  -V header-includes="\usepackage{fancyhdr} \pagestyle{fancy} \fancyhead[L]{Dilithion Whitepaper} \fancyhead[R]{v1.0 - October 2025}"
```

---

## Recommended Final PDF Settings

**For Distribution:**
- **Format:** PDF/A (archival)
- **Compression:** Medium (balance size vs quality)
- **Fonts:** Embedded (ensure compatibility)
- **Page size:** Letter (8.5" × 11") or A4
- **Margins:** 1 inch all sides
- **Font size:** 11pt body, 14-16pt headings
- **Line spacing:** 1.15-1.5
- **Include:**
  - Table of contents
  - Page numbers
  - Header/footer (optional)
  - Hyperlinks (clickable)

**File Naming:**
```
Dilithion-Whitepaper-v1.0-October-2025.pdf
```

---

## Quality Checklist

Before distributing PDF:

- [ ] All tables render correctly
- [ ] All links are clickable
- [ ] Table of contents is generated
- [ ] Page numbers are sequential
- [ ] Code blocks are readable
- [ ] No cut-off text or images
- [ ] Headers/footers appear correctly
- [ ] File size is reasonable (<5 MB)
- [ ] Fonts are embedded
- [ ] Opens in all PDF readers (Adobe, Chrome, Edge)

---

## Alternative: LaTeX Version (Advanced)

For absolute best quality, convert to LaTeX first:

```bash
# Convert markdown to LaTeX
pandoc WHITEPAPER.md -o WHITEPAPER.tex --standalone

# Edit WHITEPAPER.tex for custom formatting

# Compile to PDF
xelatex WHITEPAPER.tex
```

**Benefits:**
- Maximum control over formatting
- Professional typesetting
- Perfect for academic/technical documents

**Drawback:**
- Requires LaTeX knowledge
- More time-consuming

---

## Quick Start (Simplest Method)

**If you just need a PDF NOW:**

1. Open WHITEPAPER.md in **Chrome or Edge**
2. Press **Ctrl+P** (Print)
3. Choose "Save as PDF"
4. Adjust settings:
   - Layout: Portrait
   - Paper size: Letter
   - Margins: Default
   - Background graphics: On
5. Click "Save"

**Result:** Basic but functional PDF in 30 seconds.

---

## Recommended Pandoc Command (Final)

```bash
pandoc WHITEPAPER.md -o Dilithion-Whitepaper-v1.0.pdf \
  --pdf-engine=xelatex \
  --toc \
  --toc-depth=2 \
  --number-sections \
  --highlight-style=tango \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  -V papersize=letter \
  -V linkcolor=blue \
  -V urlcolor=blue \
  -V toccolor=black \
  --metadata title="Dilithion: A Post-Quantum Cryptocurrency" \
  --metadata subtitle="Technical Whitepaper Version 1.0" \
  --metadata author="Dilithion Core Developers" \
  --metadata date="October 2025"
```

**This produces:**
- Professional formatting
- Clickable table of contents
- Numbered sections
- Proper code highlighting
- Embedded fonts
- Optimized for printing and screen viewing

---

## Troubleshooting

### "pandoc: xelatex not found"

**Solution:** Install TeX distribution
- **Windows:** MiKTeX (https://miktex.org/)
- **Mac:** MacTeX (https://www.tug.org/mactex/)
- **Linux:** `sudo apt-get install texlive-xetex`

### Tables Don't Fit on Page

Add to pandoc command:
```bash
-V geometry:margin=0.75in
```

### Code Blocks Cut Off

Use smaller font for code:
```bash
-V monofont="Courier New" -V monofontoptions="Scale=0.85"
```

---

## Distribution Checklist

Before sharing PDF publicly:

1. **Test PDF:**
   - [ ] Opens correctly on Windows
   - [ ] Opens correctly on Mac
   - [ ] Opens correctly on mobile
   - [ ] All links work
   - [ ] No rendering issues

2. **Metadata:**
   - [ ] Title is correct
   - [ ] Author is set
   - [ ] Version number is included
   - [ ] Date is current

3. **Legal:**
   - [ ] Disclaimer is present (page 26)
   - [ ] License is clear (MIT)
   - [ ] Contact info is current

4. **Upload Locations:**
   - [ ] Website (dilithion.org)
   - [ ] GitHub repository
   - [ ] Social media (Twitter, Reddit)
   - [ ] Exchange listing applications

---

## Example Output Locations

```
website/downloads/Dilithion-Whitepaper-v1.0.pdf
github.com/dilithion/dilithion/releases/Dilithion-Whitepaper-v1.0.pdf
docs.dilithion.org/whitepaper.pdf
```

---

**Once PDF is generated, you're ready for:**
- 📧 Exchange listing applications
- 🎤 Investor presentations
- 📰 Media distribution
- 👥 Community sharing
- 🏦 Institutional review

**The whitepaper is your #1 marketing and technical document!**
