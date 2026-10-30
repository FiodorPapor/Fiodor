#!/usr/bin/env python3
import os, sys, unittest
os.environ.setdefault('RADAR_ALERT_BOT_TOKEN','test')
os.environ.setdefault('RADAR_ALERT_CHAT_ID','1')
sys.path.insert(0, '/opt/intent-radar')
import radar_bot

class RadarBotUiTests(unittest.TestCase):
    def row(self, category='POTENTIAL', username='person', chat_id=-1009999999999):
        return {'id': 42, 'category': category, 'link': 'https://t.me/example/7', 'sender_username': username,
                'chat_id': chat_id, 'text': 'Ищу квартиру в Буэнос-Айресе'}

    def texts(self, keyboard):
        return [b['text'] for row in keyboard for b in row]

    def test_potential_has_reply_and_catalog_template(self):
        texts = self.texts(radar_bot.candidate_keyboard(self.row('POTENTIAL')))
        self.assertIn('✍️ Ответить', texts)
        self.assertIn('📚 Каталог-шаблон', texts)

    def test_owner_has_reply_but_no_catalog_push(self):
        texts = self.texts(radar_bot.candidate_keyboard(self.row('OWNER_DIRECT')))
        self.assertIn('✍️ Ответить', texts)
        self.assertNotIn('📚 Каталог-шаблон', texts)

    def test_response_tools_survive_disposition(self):
        texts = self.texts(radar_bot.response_keyboard(self.row('POTENTIAL')))
        self.assertIn('✍️ Ответить', texts)
        self.assertIn('📚 Каталог-шаблон', texts)
        self.assertIn('Открыть оригинал', texts)
        self.assertNotIn('✅ Лид', texts)

    def test_catalog_templates_are_short_and_actionable(self):
        public = radar_bot.catalog_public_template()
        dm = radar_bot.catalog_dm_template()
        self.assertIn('https://t.me/lebleu_argentina_ru', public)
        self.assertIn('@paporotskiy', public)
        self.assertIn('Посмотрю ваш запрос отдельно', public)
        self.assertIn('https://t.me/lebleu_argentina_ru', dm)
        self.assertLessEqual(len(public), 256)
        self.assertLessEqual(len(dm), 256)

    def test_travelask_is_read_only_for_commercial_outreach(self):
        row = self.row('RENTER', chat_id=-1001745734197)
        texts = self.texts(radar_bot.response_keyboard(row))
        self.assertTrue(radar_bot.outreach_read_only(row))
        self.assertIn('✍️ Ответить', texts)
        self.assertNotIn('📚 Каталог-шаблон', texts)

    def test_public_default_has_no_self_promo_or_dm_cta(self):
        row = self.row('RENTER')
        public = radar_bot.generic_public(row)
        self.assertNotIn('Я Фёдор', public)
        self.assertNotIn('напишите в личку', public.lower())
        self.assertNotIn('https://', public)

if __name__ == '__main__':
    unittest.main(verbosity=2)
