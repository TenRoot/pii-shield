#!/usr/bin/env bash
# Rebuild the PDF test fixtures. Needs soffice (LibreOffice), pdftoppm and qpdf.
set -euo pipefail
cd "$(dirname "$0")"

cat > he_text.txt <<'TXT'
שם: ישראל ישראלי, ת.ז 123456782
כתובת: רחוב הרצל 12 תל אביב
Email: test@example.com
Mixed: שלום world 2024 שלום
TXT

soffice --headless --convert-to pdf he_text.txt >/dev/null
pdftoppm -r 100 -png -f 1 -l 1 he_text.pdf he_scan_src
mv he_scan_src-*.png he_scan.png
soffice --headless --convert-to pdf he_scan.png >/dev/null
qpdf --empty --pages he_text.pdf 1 he_scan.pdf 1 he_text.pdf 1 -- he_mixed.pdf
rm -f he_password.pdf
qpdf --encrypt user owner 256 -- he_text.pdf he_password.pdf

rm -f he_text.txt he_scan.png
