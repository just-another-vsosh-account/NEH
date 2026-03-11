import importlib.util
import os
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_bot_module():
    os.environ["TG_BOT_TOKEN"] = "test-token"
    os.environ["TG_ALLOWED_USER_ID"] = "1,2,3"
    spec = importlib.util.spec_from_file_location("telegram_bot_test", ROOT / "telegram-bot" / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TelegramBotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = load_bot_module()

    def test_parse_id_list_supports_multiple_values(self):
        self.assertEqual(self.bot.parse_id_list("10, 20,30"), {10, 20, 30})

    def test_default_alert_chat_uses_first_allowed_id(self):
        self.assertEqual(self.bot.DEFAULT_ALERT_CHAT_ID, 1)

    def test_help_command_returns_russian_help(self):
        messages = []

        def fake_send(chat_id, text):
            messages.append((chat_id, text))

        original = self.bot.send_message
        self.bot.send_message = fake_send
        try:
            self.bot.handle_command(1, "/help")
        finally:
            self.bot.send_message = original

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][0], 1)
        self.assertIn("Команды:", messages[0][1])
        self.assertIn("/status - сводка", messages[0][1])
