import importlib.util
import tempfile
import unittest
from pathlib import Path

DIR=Path(__file__).resolve().parent
def load(file,name):
    spec=importlib.util.spec_from_file_location(name,DIR/file)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

retire=load('tokko_retire.py','tokko_retire')
promote=load('tokko_promote.py','tokko_promote')

def row(code='A'):
    return {'code':code,'operation':'Venta','sourceUrl':'https://example.org/'+code,
            'slug':code.lower(),'tokkoSnapshotFingerprint':'versionA',
            'priceAmount':'100000','priceCurrency':'USD','imageUrls':['https://static.tokkobroker.com/example.jpg']}
def report(n,old_n):
    return {'ready_for_cutover':True,'match_conflicts':[],
            'candidate_rows':n,'legacy_catalog':old_n, 'tokko_properties':n}
class RetirementTests(unittest.TestCase):
    def test_no_missing(self):
        old=[row('A')]
        out,a,s=retire.reconcile(old,list(old),report(1,1),{},1000)
        self.assertEqual(old,out)
        self.assertFalse(a['confirmed_retirements'])
        self.assertFalse(s)
        self.assertEqual([],promote.check(old,out,a))
    def test_one_absence_holds_then_confirmed(self):
        old=[row('A'),row('B')]
        original=report(1,2)
        c1,a1,s1=retire.reconcile(old,[row('A')],original,{},1000)
        self.assertEqual(2,len(c1))
        self.assertEqual(1,len(a1['held_until_confirmed']))
        self.assertEqual([],promote.check(old,c1,a1))
        c2,a2,s2=retire.reconcile(old,[row('A')],original,s1,4700)
        self.assertEqual(1,len(c2))
        self.assertEqual(1,len(a2['confirmed_retirements']))
        self.assertEqual([],promote.check(old,c2,a2))
    def test_under_hour_holds_even_after_second_snapshot(self):
        old=[row('A'),row('B')]
        c1,a1,s1=retire.reconcile(old,[row('A')],report(1,2),{},1000)
        c2,a2,_=retire.reconcile(old,[row('A')],report(1,2),s1,1200)
        self.assertEqual(2,len(c2))
        self.assertEqual([],a2['confirmed_retirements'])
    def test_returned_row_clears_missing(self):
        old=[row('A'),row('B')]
        _,_,s1=retire.reconcile(old,[row('A')],report(1,2),{},1000)
        c2,a2,s2=retire.reconcile(old,list(old),report(2,2),s1,4700)
        self.assertEqual(2,len(c2))
        self.assertFalse(s2)
        self.assertFalse(a2['confirmed_retirements'])
    def test_promote_rejects_fake_retirement(self):
        old=[row('A'),row('B')]
        new=[row('A')]
        self.assertTrue(promote.check(old,new,report(1,2)))
    def test_too_many_removals_rejected(self):
        old=[row(str(i)) for i in range(20)]
        current=[row(str(i)) for i in range(11)]
        keys={retire.stable_key(x):{'first_absent_at':1000,'consecutive_absences':1} for x in old[11:]}
        with self.assertRaises(ValueError):
            retire.reconcile(old,current,report(11,20),keys,4800)

if __name__=='__main__':
    unittest.main()
