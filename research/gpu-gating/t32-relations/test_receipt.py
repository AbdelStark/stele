import unittest
from receipt import summarize


class RelationReceipts(unittest.TestCase):
    shape=dict(shapes=[dict(kind='relation',field=4,compact=False,count=1,variables=2,degree=3,masks=[None,0],terms=[[0,1],[]])],declared=dict(relations=1))
    log=('relation_gpu id=0 vars=2 degree=3 factors=2 terms=2 rounds=2 folds=2 finals=2 admitted=1 cpu_returned=0 '
         'host_factors_ns=1 build_ns=3 device_ns=4 cpu_oracle_ns=9 values_h2d=128 masks_h2d=16 '
         'descriptors_h2d=52 round_h2d=80 d2h=160 peak_bytes=500 total_bytes=10000 free_bytes=9000 '
         'pool_reserved=800 pool_used=100 pool_high=900\nrelation_gpu_complete relations=1 rounds=2 folds=2 finals=2')
    def test_accepts_checked_device_returns(self):
        self.assertEqual(summarize(self.log,self.shape)['by_variables']['2']['paired_device_faster'],1)
    def test_rejects_near_misses(self):
        for old,new in [('cpu_returned=0','cpu_returned=1'),('folds=2','folds=1'),('descriptors_h2d=52','descriptors_h2d=51'),
                        ('values_h2d=128','values_h2d=127'),('d2h=160','d2h=159'),('pool_high=900','pool_high=3900'),
                        ('pool_used=100','pool_used=801'),('degree=3','degree=4'),('id=0','id=1'),('masks_h2d=16','masks_h2d=15')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                summarize(self.log.replace(old,new),self.shape)


if __name__=='__main__':
    unittest.main()
