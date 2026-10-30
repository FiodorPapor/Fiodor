#!/usr/bin/env python3
import sys, unittest
sys.path.insert(0, "/opt/intent-radar")
import broad_radar

def classify(text, chat="Буэнос-Айрес · Аргентина"):
    return broad_radar.classify({"text": text, "chat_title": chat})

class BroadRadarRegressionTests(unittest.TestCase):
    def category(self, text, chat="Буэнос-Айрес · Аргентина"):
        r = classify(text, chat)
        return r[0] if r else None

    def test_explicit_buyer_not_renter(self):
        r = classify("Всем привет, хочу купить квартиру в Аргентине")
        self.assertEqual(r[0], "PROPERTY_BUYER")
        self.assertNotIn("rental_demand", r[2])

    def test_implicit_purchase_stage(self):
        self.assertEqual(self.category("Здравствуйте, подскажите где можно посмотреть варианты покупки квартиры в БА?"), "PROPERTY_BUYER")
        self.assertEqual(self.category("Я покупаю квартиру и не знаю сколько времени займёт сделка"), "PROPERTY_BUYER")

    def test_other_person_question_not_buyer(self):
        self.assertNotEqual(self.category("Как покупка квартиры вам поможет с ВНЖ?"), "PROPERTY_BUYER")

    def test_purchase_commentary_not_buyer(self):
        self.assertNotEqual(self.category("Мы тут обсуждали, что покупка квартиры в Аргентине с берега — плохая идея."), "PROPERTY_BUYER")

    def test_active_purchase_process_is_buyer(self):
        self.assertEqual(self.category("Продажа недвижимости еще в процессе, потом покупка недвижимости здесь официально."), "PROPERTY_BUYER")

    def test_service_promo_not_buyer(self):
        text = "К вашим услугам бригада профессионалов. Вы купили или планируете купить недвижимость — доверьте ремонт нам. Подскажу по материалам."
        self.assertNotEqual(self.category(text, "Аргентина объявления"), "PROPERTY_BUYER")

    def test_capital_federal_not_investor(self):
        self.assertNotEqual(self.category("Вообще-то в Капитале это стоит от 10 000 песос в час."), "INVESTOR")

    def test_product_performance_not_investor(self):
        text = "Vendo monociclo eléctrico de alto rendimiento. Palermo, CABA. Precio USD 3600."
        self.assertNotEqual(self.category(text), "INVESTOR")

    def test_generic_crypto_not_property_preintent(self):
        self.assertNotEqual(self.category("Подскажите пожалуйста, где поменять крипту на наличные?"), "PRE_INTENT")

    def test_renter(self):
        self.assertEqual(self.category("Нас двое, ищем жильё в Палермо на 3 месяца, бюджет до 700 USD"), "RENTER")

    def test_active_investment_route(self):
        text = "Мне дали ответ из консульства по моему вопросу. Сумма инвестиций обновляется. Если размер инвестиций и бизнес план устроят, можно предоставить документы."
        self.assertEqual(self.category(text), "INVESTOR")

    def test_investment_commentator_not_investor(self):
        text = "Процедура ВНЖ за инвестиции проста: вы делаете проект, показываете деньги и подаётесь, но комиссия давно не собиралась."
        self.assertNotEqual(self.category(text), "INVESTOR")

    def test_pet_home_not_property(self):
        self.assertIsNone(classify("Ищу в дом доброго котёнка, если знаете приют — напишите", "Аргентина чат"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
