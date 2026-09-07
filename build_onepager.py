# -*- coding: utf-8 -*-
"""Сборка онопейджера (≤2 МБ) под генподрядчика из материалов почты:
о нас + цена/производство + партнёры Окнотика/Рубикон + объекты с фото из референса.
Только pymupdf (fitz) — без сторонних либ. Шрифт — системный Arial (кириллица)."""
import io
import os
import fitz

BASE = os.path.dirname(os.path.abspath(__file__))
ATT = os.path.join(BASE, "mailbox", "attachments")
REF = os.path.join(ATT, "Рубикoн Референс.pdf")
OUT = os.path.join(BASE, "mailbox", "onepager_АлюмКомплект.pdf")

FONT = r"C:\Windows\Fonts\arial.ttf"
FONT_B = r"C:\Windows\Fonts\arialbd.ttf"

NAVY = (0.10, 0.20, 0.33)
GREY = (0.30, 0.33, 0.38)
LIGHT = (0.93, 0.95, 0.97)
ACCENT = (0.85, 0.45, 0.10)

W, H = 595, 842
MARGIN = 44


def extract_photos(max_n=6):
    """Вытаскивает крупные фото объектов из референса (страницы с проектами)."""
    doc = fitz.open(REF)
    seen, photos = set(), []
    for pno in range(5, len(doc)):              # чистые фото-страницы «Наши проекты» (без листа-логотипов)
        for img in doc[pno].get_images(full=True):
            xref = img[0]
            if xref in seen:
                continue
            seen.add(xref)
            try:
                pix = fitz.Pixmap(doc, xref)
                if pix.width < 380 or pix.height < 240:
                    continue
                if pix.alpha or (pix.colorspace and pix.colorspace.n >= 4):
                    pix = fitz.Pixmap(fitz.csRGB, pix)
                while pix.width > 700:
                    pix.shrink(1)
                photos.append(pix.tobytes("jpeg", jpg_quality=72))
            except Exception:
                continue
            if len(photos) >= max_n:
                doc.close()
                return photos
    doc.close()
    return photos


def reg_fonts(page):
    page.insert_font(fontname="ar", fontfile=FONT)
    page.insert_font(fontname="ab", fontfile=FONT_B)


def tb(page, x, y, w, h, text, size=10, color=GREY, bold=False, align=0, lead=1.25):
    page.insert_textbox(fitz.Rect(x, y, x + w, y + h), text, fontsize=size,
                        fontfile=(FONT_B if bold else FONT),
                        fontname=("ab" if bold else "ar"),
                        color=color, align=align, lineheight=lead)


def build():
    photos = extract_photos(6)
    doc = fitz.open()

    # ── Страница 1 ──
    p = doc.new_page(width=W, height=H)
    reg_fonts(p)
    p.draw_rect(fitz.Rect(0, 0, W, 100), color=None, fill=NAVY)
    tb(p, MARGIN, 24, W - 2 * MARGIN, 44, "ООО «АлюмКомплект»", 22, (1, 1, 1), bold=True)
    tb(p, MARGIN, 64, W - 2 * MARGIN, 28,
       "Светопрозрачные конструкции под ключ — поставка и монтаж", 12.5, (0.85, 0.9, 0.95))

    y = 120
    tb(p, MARGIN, y, W - 2 * MARGIN, 20, "ЧТО ДЕЛАЕМ", 12, NAVY, bold=True)
    y += 22
    tb(p, MARGIN, y, W - 2 * MARGIN, 70,
       "Витражи и фасадное остекление (стоечно-ригельные системы), алюминиевые окна и двери, "
       "входные группы, противопожарные витражи и окна (EI), светопрозрачная кровля и зенитные "
       "фонари, стеклопакеты под ТЗ проекта (закалённое / триплекс / армированное).", 10.5)
    y += 64

    tb(p, MARGIN, y, W - 2 * MARGIN, 20, "ПОЧЕМУ МЫ", 12, NAVY, bold=True)
    y += 22
    tb(p, MARGIN, y, W - 2 * MARGIN, 90,
       "• Собственное производство — за счёт этого стоимость даже с доставкой до объекта выходит "
       "заметно ниже средней рыночной.\n"
       "• Профильные системы: ALUTECH, ALUMARK, INICIAL, ТАТПРОФ, ALNEO; фурнитура STUBLINA, KNG, "
       "ELEMENTIS.\n"
       "• Логистика полностью отлажена — поставляем по всей России.\n"
       "• Работаем по договору: условия, порядок, ответственность прозрачно.", 10.5, lead=1.35)
    y += 92

    # блок партнёров
    p.draw_rect(fitz.Rect(MARGIN, y, W - MARGIN, y + 96), color=None, fill=LIGHT)
    tb(p, MARGIN + 14, y + 12, W - 2 * MARGIN - 28, 20, "МОНТАЖ ПОД КЛЮЧ — ПАРТНЁРЫ", 12, NAVY, bold=True)
    tb(p, MARGIN + 14, y + 34, W - 2 * MARGIN - 28, 56,
       "Монтаж на площадке и финальное предложение — через наших партнёров ООО «Окнотика» и "
       "ООО «Рубикон» с опытом монтажа сложных объектов и предоставлением гарантии. "
       "Ответственность за светопрозрачную часть объекта — на нас.", 10.5)
    y += 116

    tb(p, MARGIN, y, W - 2 * MARGIN, 20, "ОБЪЕКТЫ ПАРТНЁРОВ", 12, NAVY, bold=True)
    y += 22
    tb(p, MARGIN, y, W - 2 * MARGIN, 56,
       "Level Южнопортовая · Level Нижегородская · ЖК «Самолёт» Румянцево · А101 Прокшино · "
       "А101 Родные кварталы · «Скандинавия» · ЖК «Солнечная Долина» и «Солнечный Парк» (Щёлково).",
       10.5, color=GREY)

    # футер
    p.draw_rect(fitz.Rect(0, H - 70, W, H), color=None, fill=NAVY)
    tb(p, MARGIN, H - 58, W - 2 * MARGIN, 20, "Дмитрий Петрушкин — коммерческий директор", 12, (1, 1, 1), bold=True)
    tb(p, MARGIN, H - 36, W - 2 * MARGIN, 20,
       "ООО «АлюмКомплект»   ·   +7 906 466-63-93", 11, (0.85, 0.9, 0.95))

    # ── Страница 2: фото объектов ──
    if photos:
        p2 = doc.new_page(width=W, height=H)
        reg_fonts(p2)
        p2.draw_rect(fitz.Rect(0, 0, W, 60), color=None, fill=NAVY)
        tb(p2, MARGIN, 18, W - 2 * MARGIN, 30, "Реализованные объекты", 18, (1, 1, 1), bold=True)
        cols, gap = 2, 16
        cw = (W - 2 * MARGIN - gap) / cols
        ch = cw * 0.66
        x0, y0 = MARGIN, 84
        for i, jpg in enumerate(photos):
            r = i // cols
            c = i % cols
            x = x0 + c * (cw + gap)
            yy = y0 + r * (ch + gap)
            try:
                p2.insert_image(fitz.Rect(x, yy, x + cw, yy + ch), stream=jpg, keep_proportion=True)
            except Exception:
                pass
        tb(p2, MARGIN, H - 50, W - 2 * MARGIN, 30,
           "ООО «АлюмКомплект»   ·   Дмитрий Петрушкин   ·   +7 906 466-63-93", 10.5, GREY, align=1)

    doc.save(OUT, deflate=True, garbage=4)
    doc.close()
    size = os.path.getsize(OUT) / 1024 / 1024
    print(f"✅ Онопейджер: {OUT}  ({size:.2f} МБ, фото: {len(photos)})")


if __name__ == "__main__":
    build()
