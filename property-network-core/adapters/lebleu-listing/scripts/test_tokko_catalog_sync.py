import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('tokko_catalog_sync', Path(__file__).with_name('tokko_catalog_sync.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def obj(code='LAP123', address='Amenabar al 1500', operation='Alquiler', status=2):
    return {'id': 100, 'reference_code': code, 'address': address, 'status': status,
            'type': {'name':'Departamento'}, 'public_url':'https://ficha.info/p/example',
            'photos':[{'image':'https://static.tokkobroker.com/a.jpg'}],
            'operations':[{'operation_type':operation,'prices':[{'price':679000,'currency':'ARS'}]}],
            'description':'Luminoso, contactar: +54911012345678', 'total_surface':'40.00',
            'roofed_surface':'35.00', 'room_amount':2, 'bathroom_amount':1}


def legacy():
    return [{'code':'LAP123','operation':'Alquiler','address':'Amenabar 1500',
             'sourceUrl':'https://www.lebleu.com.ar/propiedad/amenabar-alquiler',
             'slug':'amenabar-alquiler','latitude':-34.57,'longitude':-58.45}]

class TokkoSyncTests(unittest.TestCase):
    def test_legacy_identity_preserved(self):
        rows, report = mod.build_candidate([obj()], legacy())
        self.assertEqual(1, report['legacy_matched'])
        self.assertTrue(report['ready_for_cutover'])
        self.assertEqual(legacy()[0]['sourceUrl'],rows[0]['sourceUrl'])
        self.assertEqual('amenabar-alquiler',rows[0]['slug'])
        self.assertEqual('679000',rows[0]['priceAmount'])
        self.assertNotIn('+54911', rows[0]['description'])
        self.assertNotIn('producer',rows[0])
        self.assertNotIn('lead_receiver_user',rows[0])

    def test_mismatch_blocks_cutover(self):
        rows, report = mod.build_candidate([obj(address='Calle nueva 2000')], legacy())
        self.assertFalse(report['ready_for_cutover'])
        self.assertEqual(0,report['legacy_matched'])
        self.assertEqual('https://ficha.info/p/example',rows[0]['sourceUrl'])

    def test_status_and_missing_photo_excluded(self):
        x=obj(status=3)
        y=obj(code='OTHER')
        y['id']=101
        y['photos']=[]
        rows, report=mod.build_candidate([x,y],legacy())
        self.assertFalse(rows)
        self.assertEqual(1, report['skipped_reasons']['not_available_status'])
        self.assertEqual(1, report['skipped_reasons']['incomplete_public_facts'])

    def test_multiple_operations_separate_without_legacy_rewrite(self):
        x=obj(code='NO_OLD')
        x['operations'].append({'operation_type':'Venta','prices':[{'price':190000,'currency':'USD'}]})
        rows,report=mod.build_candidate([x],legacy())
        self.assertEqual(2,len(rows))
        self.assertEqual({'Alquiler','Venta'},{r['operation'] for r in rows})
        self.assertFalse(report['ready_for_cutover'])
        self.assertTrue(all('tokko-' in r['slug'] for r in rows))

    def test_large_tokko_id_not_rejected(self):
        x=obj(code='LAP123')
        x['id']=14346637
        rows, report=mod.build_candidate([x],legacy())
        self.assertEqual(1,len(rows))
        self.assertEqual(0,report['skipped_reasons'].get('invalid_tokko_id',0))

    def test_secondary_matching_repairs_scraper_address_not_real_change(self):
        x=obj(code='LAP123', address='Maure al 4000', operation='Venta')
        x['operations'][0]['prices'][0]={'price':129900,'currency':'USD'}
        x['total_surface']='45.50'
        x['description']='Venta monoambiente en Maure 4000, con balcón, espacioso living'
        old=[dict(legacy()[0],code='LAP123',operation='Venta', propertyType='Departamento',
                  priceCurrency='USD',priceAmount='129900',details={'totalAreaM2':45.5},
                  description=x['description'],address='Gran ubicación en Chacarita')]
        rows,report=mod.build_candidate([x],old)
        self.assertTrue(report['ready_for_cutover'])
        self.assertEqual(1,len(report['secondary_matches']))
        self.assertEqual(old[0]['sourceUrl'],rows[0]['sourceUrl'])
        self.assertEqual('Maure al 4000',rows[0]['address'])

    def test_feature_tags_and_zero_rooms(self):
        x=obj()
        x['tags']=[{'name':'Balcón'},{'name':'SUM'},{'name':'Laundry'},{'name':'garbage'}]
        x['room_amount']=0
        rows,_=mod.build_candidate([x],legacy())
        self.assertEqual({'Balcón','SUM','Laundry'},set(rows[0]['highlightedFeatures']))
        self.assertNotIn('rooms',rows[0]['details'])

    def test_sale_and_rent_same_tokko_link_must_block_public_token_collision(self):
        x=obj(code='NO_OLD')
        x['operations'].append({'operation_type':'Venta','prices':[{'price':190000,'currency':'USD'}]})
        rows,report=mod.build_candidate([x],legacy())
        self.assertEqual(2,len(rows))
        self.assertTrue(any(c['type']=='duplicate_public_listing_tokens' for c in report['match_conflicts']))

    def test_reviewed_content_fingerprints_survive_first_tokko_baseline(self):
        x=obj()
        old=legacy()
        old[0].update(priceAmount='679000',priceCurrency='ARS',sourceFingerprint='old-source-review',
                      ruContentFingerprint='old-ru-review',highlightedFeatures=['Balcón'],
                      details={'totalAreaM2':40,'bedrooms':1},description='Luminoso, listo para habitar')
        rows,report=mod.build_candidate([x],old)
        self.assertEqual('old-source-review',rows[0]['sourceFingerprint'])
        self.assertEqual('old-ru-review',rows[0]['ruContentFingerprint'])
        self.assertIn('Balcón',rows[0]['highlightedFeatures'])
        self.assertEqual(1,rows[0]['details']['bedrooms'])
        self.assertTrue(rows[0]['tokkoSnapshotFingerprint'])
        rows2,_=mod.build_candidate([x],rows)
        self.assertEqual('old-ru-review',rows2[0]['ruContentFingerprint'])
        x['operations'][0]['prices'][0]['price']=700000
        rows3,_=mod.build_candidate([x],rows2)
        self.assertNotEqual('old-source-review',rows3[0]['sourceFingerprint'])
        self.assertNotEqual('old-ru-review',rows3[0]['ruContentFingerprint'])

    def test_output_guard(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'fixture.json'; f.write_text(json.dumps({'objects':[obj()]}))
            o=Path(d)/'old.json'; o.write_text(json.dumps(legacy()))
            result=__import__('subprocess').run(['python3',str(Path(mod.__file__)), '--fixture',str(f),'--legacy',str(o),'--output-dir',str(Path(d)/'stage')],capture_output=True,text=True)
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertEqual(1,len(json.loads((Path(d)/'stage/candidate-catalog.json').read_text())))

if __name__=='__main__':
    unittest.main()
