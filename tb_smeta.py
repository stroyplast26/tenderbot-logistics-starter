# -*- coding: utf-8 -*-
"""V2: извлечение текста сметы/ВОР и выжимка строк про остекление для ИИ.

Поддержка форматов: .xlsx/.xls (openpyxl), .docx (python-docx), .pdf (PyMuPDF).
Сканы-PDF (картинки) пропускаем (нужен OCR) — честно возвращаем пусто.
"""
import io
import logging
import re

log = logging.getLogger("tenderbot")

# названия файлов, похожих на смету/ведомость объёмов/локальный сметный расчёт.
# Границы для ВОР/ЛСР — по БУКВАМ (не \b), иначе "_ЛСР-02" не ловится (подчёркивание = \w),
# а "договор" не должен ловиться по "вор".
SMETA_NAME_RE = re.compile(
    r"(смет|ведомост|об[ъь][её]м|локальн|сводн.*расч|расчет\s*стоим"
    r"|(?<![а-яёa-z])лср(?![а-яёa-z])"
    r"|(?<![а-яёa-z])вор(?![а-яёa-z]))",
    re.IGNORECASE)

# строки сметы, относящиеся к нашему профилю (остекление и сопутствующее)
GLAZING_LINE_RE = re.compile(
    r"(остекл|витраж|светопроз|фасад|окон|окно|оконн|стекл|стеклопак|алюмини|"
    r"двер|профил|зенитн|стоечно|ригел|входн.*групп|противопожар|огнестойк|"
    r"\bei\W?\d|\beiw|нащельник|штапик)",
    re.IGNORECASE)


def find_smeta_docs(docs):
    """Из списка {'name','url'} оставляет похожие на смету/ВОР/ЛСР."""
    return [d for d in (docs or []) if d.get("name") and SMETA_NAME_RE.search(d["name"])]


# документы с описанием работ/объёмов (когда нет файла «смета»): ТЗ, ООЗ, приложения, проект контракта
SCOPE_NAME_RE = re.compile(
    r"техническ\w*\s*задани|\bт\W?з\b|обоснование\s*объекта|\bооз\b|описание\s*объект|"
    r"описание\s*закупк|приложение|проект\s*контракт|проект\s*договор|спецификац|ведомост|"
    r"проектн\w*\s*документ|рабоч\w*\s*документ|документац|комплект|состав\s*документ|\bпд\b",
    re.IGNORECASE)
# то, что НЕ содержит объёмов работ (исключаем из чтения) — только процедурные документы
NOT_SCOPE_RE = re.compile(
    r"требовани\w*\s*к\s*заявк|инструкц\w*\s*по|\bреестр\b|протокол\s|банковск\w*\s*гарант|"
    r"обеспечение\s*(заявк|исполн)",
    re.IGNORECASE)


def scope_docs(docs):
    """Документы для чтения ИИ по приоритету: смета > ТЗ/ООЗ > приложения/проект контракта."""
    smeta = find_smeta_docs(docs)
    smeta_urls = {d.get("url") for d in smeta}
    rest = [d for d in (docs or [])
            if d.get("name") and d.get("url") not in smeta_urls
            and SCOPE_NAME_RE.search(d["name"]) and not NOT_SCOPE_RE.search(d["name"])]

    def rank(d):
        nm = d.get("name", "").lower()
        if re.search(r"техническ|задани|обоснование\s*объект|\bооз\b|описание\s*объект", nm):
            return 0
        if re.search(r"приложение", nm):
            return 1
        return 2

    rest.sort(key=rank)
    return smeta + rest


# чертёжные/инженерные разделы — большие PDF, для ЧТЕНИЯ текста их не качаем (идут во вложения)
DRAWING_SECTION_RE = re.compile(
    r"чертеж|графическ|раздел\s*пд|\bпд\s*№|\bар\b|\bкр\b|\bпос\b|\bовик\b|\bов\b|\bвк\b|"
    r"\bэом\b|\bнвк\b|\bсс\b|\bгп\b|\bиос\b|\bпб\b|наружн\w*\s*сет|благоустр|организац\w*\s*строит",
    re.IGNORECASE)


def is_drawing_section(name):
    """True, если документ — чертёж/инженерный раздел (не текст со сметой/объёмами)."""
    low = (name or "").lower()
    if not DRAWING_SECTION_RE.search(low):
        return False
    # но смета/ВОР/пояснительная записка — это ТЕКСТ, читаем
    if SMETA_NAME_RE.search(low) or re.search(r"\bсм\b|сметн|пояснительн|\bпз\b", low):
        return False
    return True


def _from_xlsx(content: bytes) -> str:
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    out = []
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            cells = [str(c) for c in row if c not in (None, "")]
            if cells:
                out.append(" | ".join(cells))
    wb.close()
    return "\n".join(out)


def _from_docx(content: bytes) -> str:
    import docx
    d = docx.Document(io.BytesIO(content))
    out = [p.text for p in d.paragraphs if p.text.strip()]
    for t in d.tables:
        for row in t.rows:
            cells = [c.text.strip() for c in row.cells if c.text.strip()]
            if cells:
                out.append(" | ".join(cells))
    return "\n".join(out)


def _ocr_image(content: bytes) -> str:
    """Optional local OCR. Empty result is safe when the engine is unavailable."""
    try:
        import pytesseract
        from PIL import Image
        image = Image.open(io.BytesIO(content))
        return pytesseract.image_to_string(image, lang="rus+eng", config="--psm 6")
    except Exception as e:
        log.info("OCR unavailable or failed: %s", e)
        return ""


def _ocr_pdf(content: bytes, max_pages: int = 6) -> str:
    try:
        import fitz
    except Exception:
        return ""
    parts = []
    try:
        with fitz.open(stream=content, filetype="pdf") as doc:
            for page in list(doc)[:max_pages]:
                pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                text = _ocr_image(pix.tobytes("png"))
                if text.strip():
                    parts.append(text)
    except Exception as e:
        log.info("PDF OCR failed: %s", e)
    return "\n".join(parts)


def _from_pdf(content: bytes) -> str:
    import fitz
    text = []
    with fitz.open(stream=content, filetype="pdf") as doc:
        for page in doc:
            text.append(page.get_text())
    raw = "\n".join(text)
    return raw if len(raw.strip()) > 80 else _ocr_pdf(content)


def _from_zip(content: bytes, depth: int) -> str:
    """Читает смету/документы ВНУТРИ архива .zip (приоритет: смета > ТЗ/ООЗ > прочее)."""
    import zipfile
    out, total = [], 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except Exception:
        return ""
    names = [n for n in zf.namelist()
             if n.lower().endswith((".xlsx", ".xlsm", ".docx", ".pdf"))]

    def rank(n):
        low = n.lower()
        if SMETA_NAME_RE.search(low):
            return 0
        if SCOPE_NAME_RE.search(low):
            return 1
        return 2

    for n in sorted(names, key=rank)[:10]:
        try:
            data = zf.read(n)
        except Exception:
            continue
        txt = extract_text(n, data, depth + 1)
        if txt:
            out.append(txt)
            total += len(txt)
            if total > 300000:
                break
    return "\n".join(out)


def extract_text(filename: str, content: bytes, depth: int = 0) -> str:
    """Текст из файла по расширению (включая смету ВНУТРИ .zip). Пусто, если скан/не поддержано."""
    fn = (filename or "").lower()
    if depth > 2:
        return ""
    try:
        if fn.endswith((".xlsx", ".xlsm")):
            return _from_xlsx(content)
        if fn.endswith(".docx"):
            return _from_docx(content)
        if fn.endswith(".pdf"):
            txt = _from_pdf(content)
            # скан без текстового слоя — пусто (нужен OCR, не делаем)
            return txt if len(txt.strip()) > 80 else ""
        if fn.endswith((".png", ".jpg", ".jpeg", ".tif", ".tiff")):
            txt = _ocr_image(content)
            return txt if len(txt.strip()) > 20 else ""
        if fn.endswith(".zip"):
            return _from_zip(content, depth)
        # .xls (старый), .doc, .rar — пока не разбираем
        return ""
    except Exception as e:
        log.warning("    документ %s не разобран: %s", filename, e)
        return ""


# страницы чертежей, которые нас интересуют (наша часть + общий фасад здания)
DRAWING_PAGE_RE = re.compile(
    r"фасад|витраж|остекл|окон|окно|светопроз|алюмини|стеклопак|"
    r"входн\w*\s*групп|зенитн|стоечно|ригел|п\W?в\W?х\b",
    re.IGNORECASE)
FACADE_RE = re.compile(r"фасад", re.IGNORECASE)


def extract_pdf_pages(content: bytes, max_pages: int = 25):
    """Из born-digital PDF вырезает листы про остекление + общий фасад в новый небольшой PDF.

    Возвращает (bytes_pdf, число_листов) или (None, 0), если PDF — скан без текста
    (тогда листы не определить) или ничего не найдено.
    """
    try:
        import fitz
    except Exception:
        return None, 0
    try:
        doc = fitz.open(stream=content, filetype="pdf")
    except Exception:
        return None, 0
    npages = doc.page_count
    text_total = 0
    page_text = []
    for p in doc:
        t = p.get_text()
        page_text.append(t)
        text_total += len(t)
    # скан без текстового слоя — листы не определить
    if text_total < 50 * max(1, npages):
        doc.close()
        return None, 0
    glaz_pages = [i for i, t in enumerate(page_text) if DRAWING_PAGE_RE.search(t)]
    facade_pages = [i for i, t in enumerate(page_text) if FACADE_RE.search(t)]
    pages = sorted(set(glaz_pages) | set(facade_pages))
    if not pages:
        doc.close()
        return None, 0
    pages = pages[:max_pages]
    out = fitz.open()
    for i in pages:
        out.insert_pdf(doc, from_page=i, to_page=i)
    data = out.tobytes(garbage=4, deflate=True)
    out.close()
    doc.close()
    return data, len(pages)


def glazing_excerpt(text: str, max_chars: int = 6000) -> str:
    """Выжимка: строки про остекление (+ соседние), обрезано до max_chars."""
    if not text:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    keep = []
    seen = set()
    for ln in lines:
        if GLAZING_LINE_RE.search(ln):
            # чистим лишние пробелы, ограничиваем длину строки
            clean = re.sub(r"\s+", " ", ln)[:300]
            if clean.lower() not in seen:
                seen.add(clean.lower())
                keep.append(clean)
    excerpt = "\n".join(keep)
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars] + " …(обрезано)"
    return excerpt
