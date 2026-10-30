#!/usr/bin/env python3
import sys, unittest
sys.path.insert(0, "/opt/intent-radar")
import lebleu_matcher as m

class LeBleuMatcherTests(unittest.TestCase):
    def test_russian_room_slang(self):
        self.assertEqual(m.parse_query("аренда трёшка Belgrano")["rooms"], 3)
        self.assertEqual(m.parse_query("аренда двушка Belgrano")["rooms"], 2)
        self.assertEqual(m.parse_query("купить однушку Palermo")["rooms"], 1)

    def test_parque_centenario(self):
        q=m.parse_query("аренда трешка около парка Сентенарио")
        self.assertIn("parque centenario",q["neighborhoods"])

    def test_apartment_query_excludes_commercial(self):
        rows=m.search("аренда двушка Belgrano до 1200 USD",limit=20)
        self.assertTrue(rows)
        self.assertTrue(all(m.effective_type(x["item"]) in {"Departamento","PH","Casa"} for x in rows))

    def test_suspicious_sale_price_not_matched(self):
        item={"operation":"Venta","priceCurrency":"USD","priceAmount":1,"propertyType":"Local Comercial","sourceUrl":"x","sourceFingerprint":"x"}
        self.assertIsNone(m.score_item(item,{"operation":"Venta","neighborhoods":[],"max_budget":100000,"budget_currency":"USD","rooms":None,"bedrooms":None,"features":[],"direct_owner_only":False,"residential_only":False,"raw":""}))

if __name__=="__main__":
    unittest.main(verbosity=2)
