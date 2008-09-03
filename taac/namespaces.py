# Some URIs.
class namespace:
    def __init__(self, uri):
        self.uri = uri

    def __getattr__(self, name):
        return self.uri + name

    def __getitem__(self, key):
        return self.uri + key

rdf = namespace('http://www.w3.org/1999/02/22-rdf-syntax-ns#')
rein = namespace('http://dig.csail.mit.edu/2005/09/rein/network#')
tami = namespace('http://dig.csail.mit.edu/TAMI/2007/tami#')
foaf = namespace('http://xmlns.com/foaf/0.1/')
air = namespace('http://dig.csail.mit.edu/TAMI/2007/amord/air#')
