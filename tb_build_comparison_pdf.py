# -*- coding: utf-8 -*-
"""Строит 1-страничный PDF-сравнение цен по реальному объекту (для вложения в письма).
Данные: реальное КП АлюмКомплект (520 000 ₽) vs дилерский заказ Alumark 2184739 (627 164 ₽),
один и тот же объект (Alumark S158, 10,97 м²), обе цены с НДС и доставкой. Рыночная цена обезличена.
"""
import argparse
import os
from pathlib import Path

import fitz

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = PROJECT_DIR / "mailbox" / "Сравнение_цен_АлюмКомплект.pdf"

MARKET = 627164
OURS = 520000
SAVE = MARKET - OURS                       # 107 164
PCT_MORE = round((MARKET - OURS) / OURS * 100)   # рынок дороже на ~21%


def money(n):
    return f"{n:,}".replace(",", " ") + " ₽"


HTML = f"""
<div style="font-family:sans-serif;color:#1a1a1a;">
  <div style="background:#305496;color:#ffffff;padding:16px 20px;">
    <div style="font-size:21px;font-weight:bold;">ООО «АлюмКомплект» — завод алюминиевого остекления</div>
    <div style="font-size:13px;margin-top:3px;">Сравнение стоимости на реальном объекте</div>
  </div>
  <div style="padding:18px 20px;">
    <div style="font-size:13px;color:#444;line-height:1.5;">
      <b>Объект:</b> подъёмно-раздвижные порталы Alumark S158 — 2 шт., 10,97 м²,
      стеклопакет СПД40, RAL 8014.<br>
      Обе цены — <b>с НДС и доставкой</b>, одинаковая система и комплектация.
    </div>
    <table style="width:100%;border-collapse:collapse;margin-top:16px;">
      <tr>
        <td style="padding:16px;background:#f4f4f4;border:1px solid #dddddd;width:50%;text-align:center;">
          <div style="color:#888888;font-size:13px;">Рыночная цена (дилер)</div>
          <div style="font-size:27px;font-weight:bold;color:#b00020;margin-top:4px;">{money(MARKET)}</div>
        </td>
        <td style="padding:16px;background:#e7f4ea;border:1px solid #bcdfc6;width:50%;text-align:center;">
          <div style="color:#2e7d32;font-size:13px;">АлюмКомплект (завод, Ставрополь)</div>
          <div style="font-size:27px;font-weight:bold;color:#1b7a2f;margin-top:4px;">{money(OURS)}</div>
        </td>
      </tr>
    </table>
    <div style="margin-top:16px;background:#1b7a2f;color:#ffffff;padding:16px;text-align:center;">
      <div style="font-size:15px;">Ваша экономия на одном объекте</div>
      <div style="font-size:31px;font-weight:bold;margin-top:2px;">{money(SAVE)}</div>
      <div style="font-size:14px;margin-top:2px;">рынок дороже более чем на {PCT_MORE}%</div>
    </div>
    <div style="margin-top:16px;font-size:14px;color:#333333;line-height:1.5;">
      На разных объектах разница составляет <b>20–30%</b> — за счёт собственного производства
      и прямой поставки с завода без посредников. Профиль и фурнитура — того же класса
      (Alumark, Alutech, Татпроф): экономия на себестоимости, а не на качестве.
    </div>
    <div style="margin-top:16px;font-size:15px;color:#111111;font-weight:bold;">
      Пришлите свой чертёж, смету или ведомость — посчитаем так же по вашему объекту
      в течение рабочего дня.
    </div>
    <div style="margin-top:20px;font-size:13px;color:#555555;border-top:1px solid #dddddd;padding-top:10px;">
      ООО «АлюмКомплект» · Дмитрий Петрушкин, коммерческий директор · +7 906 466-63-93<br>
      <span style="font-size:10px;color:#999999;">Рыночная цена приведена по коммерческому предложению
      на аналогичный объект (та же система и комплектация), с НДС и доставкой. Данные обезличены.</span>
    </div>
  </div>
</div>
"""


def build(output=DEFAULT_OUT):
    output = Path(output).expanduser()
    if not output.is_absolute():
        output = PROJECT_DIR / output
    output = output.resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)   # A4
    rect = fitz.Rect(28, 28, 567, 814)
    spare = page.insert_htmlbox(rect, HTML)
    doc.save(os.fspath(output))
    doc.close()
    print(f"✅ {output}")
    print(f"   рынок {money(MARKET)} | наше {money(OURS)} | экономия {money(SAVE)} (рынок +{PCT_MORE}%)")
    print(f"   spare height: {spare}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Построить PDF сравнения цен")
    parser.add_argument("--output", default=os.fspath(DEFAULT_OUT), help="путь итогового PDF")
    build(parser.parse_args().output)
