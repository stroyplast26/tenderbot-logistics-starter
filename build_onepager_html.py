# -*- coding: utf-8 -*-
"""Онопейджер v2 — через HTML/CSS → PDF (Edge headless). Дизайн: hero-фото фасада с
оверлеем, строка цифр-преимуществ, что делаем, партнёры, сетка объектов с подписями.
Фото — из референса (base64, self-contained). Размер держим ≤2 МБ."""
import base64
import os
import subprocess
import fitz

BASE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(BASE, "mailbox", "op_img")
HTML = os.path.join(BASE, "mailbox", "onepager.html")
PDF = os.path.join(BASE, "mailbox", "onepager_АлюмКомплект.pdf")
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


def b64(name, max_w, q=80):
    pix = fitz.Pixmap(os.path.join(IMG, name))
    if pix.alpha or (pix.colorspace and pix.colorspace.n >= 4):
        pix = fitz.Pixmap(fitz.csRGB, pix)
    while pix.width > max_w:
        pix.shrink(1)
    data = pix.tobytes("jpeg", jpg_quality=q)
    return "data:image/jpeg;base64," + base64.b64encode(data).decode()


HERO = b64("p12.jpg", 1300, 82)
GAL = [b64(n, 700, 78) for n in ("p3.jpg", "p1.jpg", "p11.jpg", "p6.jpg", "p5.jpg", "p7.jpg")]

HTML_DOC = f"""<!doctype html><html><head><meta charset="utf-8"><style>
* {{ margin:0; padding:0; box-sizing:border-box; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
@page {{ size:A4; margin:0; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; color:#1b2430; }}
.page {{ width:210mm; height:297mm; position:relative; overflow:hidden; page-break-after:always; }}
.page:last-child {{ page-break-after:auto; }}

.hero {{ height:118mm; background:linear-gradient(180deg,rgba(13,26,45,.30),rgba(13,26,45,.86)),
        url('{HERO}'); background-size:cover; background-position:center; color:#fff;
        display:flex; flex-direction:column; justify-content:flex-end; padding:14mm 16mm; }}
.eyebrow {{ font-size:12pt; letter-spacing:3px; color:#e6b873; font-weight:600; text-transform:uppercase; }}
.h1 {{ font-size:30pt; font-weight:700; line-height:1.12; margin:4mm 0 3mm; max-width:150mm; }}
.sub {{ font-size:13pt; color:#dfe7f0; }}

.stats {{ display:flex; background:#0d1a2d; color:#fff; }}
.stat {{ flex:1; padding:7mm 5mm; text-align:center; border-right:1px solid rgba(255,255,255,.12); }}
.stat:last-child {{ border-right:none; }}
.stat .big {{ font-size:19pt; font-weight:700; color:#e6b873; }}
.stat .lbl {{ font-size:9.5pt; color:#cdd8e6; margin-top:2mm; }}

.body {{ padding:11mm 16mm; }}
.sec-h {{ font-size:13pt; font-weight:700; color:#0d1a2d; letter-spacing:.5px;
         border-left:4px solid #e6b873; padding-left:3mm; margin-bottom:4mm; }}
.lead {{ font-size:11pt; line-height:1.6; color:#33414f; }}
.chips {{ display:flex; flex-wrap:wrap; gap:3mm; margin-top:4mm; }}
.chip {{ background:#eef2f7; color:#1b2430; border-radius:20px; padding:2.4mm 5mm; font-size:10pt; }}
.split {{ margin-top:9mm; }}

.partners {{ margin-top:9mm; background:#f3f6fa; border-radius:8px; padding:7mm; }}
.partners .nm {{ font-weight:700; color:#0d1a2d; }}

.footer {{ position:absolute; bottom:0; left:0; right:0; background:#0d1a2d; color:#fff;
          padding:7mm 16mm; display:flex; justify-content:space-between; align-items:center; }}
.footer .who {{ font-size:13pt; font-weight:700; }}
.footer .role {{ font-size:10pt; color:#cdd8e6; }}
.footer .tel {{ font-size:16pt; font-weight:700; color:#e6b873; }}

.gal-head {{ padding:12mm 16mm 5mm; }}
.gal-head .t {{ font-size:22pt; font-weight:700; color:#0d1a2d; }}
.gal-head .s {{ font-size:11pt; color:#5a6a7a; margin-top:2mm; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:4mm; padding:0 16mm; }}
.cell {{ height:52mm; border-radius:6px; overflow:hidden; }}
.cell img {{ width:100%; height:100%; object-fit:cover; }}
.objlist {{ padding:9mm 16mm; font-size:10.5pt; line-height:1.7; color:#33414f; }}
.objlist b {{ color:#0d1a2d; }}
</style></head><body>

<div class="page">
  <div class="hero">
    <div class="eyebrow">ООО «АлюмКомплект»</div>
    <div class="h1">Светопрозрачные конструкции<br>под ключ</div>
    <div class="sub">Витражи · фасадное остекление · окна и двери · противопожарные (EI) · поставка и монтаж по всей России</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="big">−25–35%</div><div class="lbl">к рыночной цене за счёт<br>собственного производства</div></div>
    <div class="stat"><div class="big">Под ключ</div><div class="lbl">поставка + монтаж<br>с гарантией</div></div>
    <div class="stat"><div class="big">Вся РФ</div><div class="lbl">отлаженная логистика,<br>доставка до объекта</div></div>
    <div class="stat"><div class="big">5 систем</div><div class="lbl">ALUTECH, ALUMARK,<br>INICIAL, ТАТПРОФ, ALNEO</div></div>
  </div>

  <div class="body">
    <div class="sec-h">ЧТО ДЕЛАЕМ</div>
    <div class="lead">Производим алюминиевые светопрозрачные конструкции под объект любой сложности — от расчёта до монтажа.</div>
    <div class="chips">
      <span class="chip">Витражи</span><span class="chip">Фасадное остекление</span>
      <span class="chip">Стоечно-ригельные системы</span><span class="chip">Окна и двери</span>
      <span class="chip">Входные группы</span><span class="chip">Противопожарные EI</span>
      <span class="chip">Зенитные фонари</span><span class="chip">Стеклопакеты под ТЗ</span>
    </div>

    <div class="partners">
      <div class="sec-h" style="margin-bottom:3mm">МОНТАЖ ПОД КЛЮЧ — ПАРТНЁРЫ</div>
      <div class="lead">Монтаж на площадке и финальное предложение — через партнёров <span class="nm">ООО «Окнотика»</span>
      и <span class="nm">ООО «Рубикон»</span> с опытом монтажа сложных объектов и гарантией.
      Ответственность за светопрозрачную часть объекта — на нас.</div>
    </div>
  </div>

  <div class="footer">
    <div><div class="who">Дмитрий Петрушкин</div><div class="role">Коммерческий директор · ООО «АлюмКомплект»</div></div>
    <div class="tel">+7 906 466-63-93</div>
  </div>
</div>

<div class="page">
  <div class="gal-head">
    <div class="t">Реализованные объекты партнёров</div>
    <div class="s">Жилые комплексы и общественные здания в Москве и регионах</div>
  </div>
  <div class="grid">
    {''.join(f'<div class="cell"><img src="{g}"></div>' for g in GAL)}
  </div>
  <div class="objlist">
    <b>Среди объектов:</b> Level Южнопортовая · Level Нижегородская · ЖК «Самолёт» Румянцево ·
    А101 Прокшино · А101 Родные кварталы · «Скандинавия» · ЖК «Солнечная Долина» и «Солнечный Парк» (Щёлково).
  </div>
  <div class="footer">
    <div><div class="who">Готовы посчитать ваш объект</div><div class="role">ООО «АлюмКомплект» · Дмитрий Петрушкин</div></div>
    <div class="tel">+7 906 466-63-93</div>
  </div>
</div>

</body></html>"""


def main():
    with open(HTML, "w", encoding="utf-8") as f:
        f.write(HTML_DOC)
    if os.path.exists(PDF):
        try:
            os.remove(PDF)
        except Exception:
            pass
    url = "file:///" + HTML.replace("\\", "/")
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={PDF}", "--virtual-time-budget=6000", url],
                   timeout=90, capture_output=True)
    if os.path.exists(PDF):
        print("PDF MB:", round(os.path.getsize(PDF) / 1024 / 1024, 2))
    else:
        print("PDF не создан")


if __name__ == "__main__":
    main()
