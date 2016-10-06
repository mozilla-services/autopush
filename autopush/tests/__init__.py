class MockAssist(object):
    def __init__(self, results):
        self.cur = 0
        self.max = len(results)
        self.results = results

    def __call__(self, *args, **kwargs):
        try:
            r = self.results[self.cur]
            print r
            if callable(r):
                return r()
            else:
                return r
        finally:
            if self.cur < (self.max - 1):
                self.cur += 1
