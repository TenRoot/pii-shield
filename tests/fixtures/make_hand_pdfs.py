"""Write small hand-made PDF fixtures. Standard library only.

Run from this folder:  ../../.venv/bin/python -I make_hand_pdfs.py
All values are invented.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = b"<< /Type /XObject /Subtype /Image /Width 4 /Height 4 /ColorSpace /DeviceGray " \
        b"/BitsPerComponent 8 /Length 16 >>\nstream\n" + bytes([200] * 16) + b"\nendstream"
FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"


def stream(data: bytes, extra: bytes = b"") -> bytes:
    return b"<< " + extra + b"/Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


def write_pdf(name: str, objs) -> None:
    """objs: object bodies; object i+1 is objs[i]. Object 1 must be the catalog."""
    out = bytearray(b"%PDF-1.7\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offsets:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    (HERE / name).write_bytes(bytes(out))


def form_filled() -> None:
    """A filled text field (test@example.com) and a FreeText note (ID 123456782).

    The page content has only the form label, so the values are in the annotations only.
    """
    content = b"BT /F1 14 Tf 72 700 Td (Application form for the customer account) Tj ET"
    ap_field = b"BT /F1 12 Tf 2 5 Td (test@example.com) Tj ET"
    ap_note = b"BT /F1 12 Tf 2 5 Td (ID 123456782) Tj ET"
    ap_res = b"/Type /XObject /Subtype /Form /BBox [0 0 228 20] /Resources << /Font << /F1 4 0 R >> >> "
    write_pdf("form_filled.pdf", [
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] /DR << /Font << /F1 4 0 R >> >> >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> "
        b"/Contents 5 0 R /Annots [6 0 R 8 0 R] >>",
        FONT,
        stream(content),
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (email) /V (test@example.com) /Rect [72 600 300 620] "
        b"/P 3 0 R /AP << /N 7 0 R >> /F 4 >>",
        stream(ap_field, ap_res),
        b"<< /Type /Annot /Subtype /FreeText /Contents (ID 123456782) /DA (/F1 12 Tf 0 g) "
        b"/Rect [72 500 300 520] /P 3 0 R /AP << /N 9 0 R >> /F 4 >>",
        stream(ap_note, ap_res),
    ])


def form_xobject_scan() -> None:
    """A page-size scan inside a Form XObject: the form is scaled to the page, the image is unit size."""
    content = b"q 612 0 0 792 0 0 cm /Fm1 Do Q BT /F1 14 Tf 72 40 Td (Page footer text with stamp line 12) Tj ET"
    write_pdf("form_xobject_scan.pdf", [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> /XObject << /Fm1 6 0 R >> >> /Contents 5 0 R >>",
        FONT,
        stream(content),
        stream(b"/Im1 Do", b"/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /Im1 7 0 R >> >> "),
        IMAGE,
    ])


def little_text_scan() -> None:
    """A page-size image with a short text layer (a page number)."""
    content = b"q 612 0 0 792 0 0 cm /Im1 Do Q BT /F1 10 Tf 300 20 Td (page 7) Tj ET"
    write_pdf("little_text_scan.pdf", [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> /XObject << /Im1 6 0 R >> >> /Contents 5 0 R >>",
        FONT,
        stream(content),
        IMAGE,
    ])


if __name__ == "__main__":
    form_filled()
    form_xobject_scan()
    little_text_scan()
