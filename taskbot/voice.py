from __future__ import annotations


class VoiceNotConfigured(RuntimeError):
    pass


def explain_voice_setup(provider: str) -> str:
    if provider == "yandex":
        return "Для Yandex SpeechKit не задан API-ключ. Голосовое не было скачано и не сохранено."
    return "Распознавание голоса ещё не настроено. Нужен ключ Yandex SpeechKit или OpenAI для русского STT."
