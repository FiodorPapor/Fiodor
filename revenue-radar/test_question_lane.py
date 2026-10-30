#!/usr/bin/env python3
import unittest
import question_lane as q

def row(text, topic="emerging:test", chat="Все русские в Аргентине"):
    return {"text": text, "topic": topic, "chat_title": chat}

class QuestionLaneTests(unittest.TestCase):
    def test_rental_question(self):
        self.assertTrue(q._relevant(row("Подскажите, где можно снять квартиру без подтверждения дохода?", "rental")))

    def test_purchase_question(self):
        self.assertTrue(q._relevant(row("Подскажите где посмотреть варианты покупки квартиры в БА ?")))

    def test_due_diligence_question(self):
        self.assertTrue(q._relevant(row("Правильно понимаю, что любой риэлтор проверяет это до внесения резерва?")))

    def test_yoga_promo_is_not_property_question(self):
        self.assertFalse(q._relevant(row("Приглашаю на мои уроки хатха йоги. Ищете способ снять стресс?")))

    def test_job_post_is_not_property_question(self):
        self.assertFalse(q._relevant(row("Ищу работу, готов рассмотреть предложения в любой сфере. Кто может подсказать?")))

    def test_rental_listing_is_not_question(self):
        self.assertFalse(q._relevant(row("Свободна с 01.10.2026. Сдаётся квартира 850 USD + expensas. Пишите в личку.")))

if __name__ == "__main__":
    unittest.main()
