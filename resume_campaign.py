# -*- coding: utf-8 -*-
"""Снимает паузу кампании (mode=live, paused=False). Запускается одноразовой задачей Планировщика
на 09:00, чтобы кампания возобновилась сама по утреннему плану (Л1=50/Л2=150, темп ≤20/час)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tb_control

tb_control.update(mode="live", paused=False)
