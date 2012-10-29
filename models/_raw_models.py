from google.appengine.ext import ndb

class Program(ndb.Model):
  title = ndb.StringProperty()
  slug = ndb.StringProperty()
  desc = ndb.StringProperty()
  dj_list = ndb.KeyProperty(repeated=True)
  page_html = ndb.TextProperty()
  top_artists = ndb.StringProperty(repeated=True)
  top_playcounts = ndb.IntegerProperty(repeated=True)
  current = ndb.BooleanProperty(default=False)

class Album(ndb.Model):
  title = ndb.StringProperty(required=True)
  asin = ndb.StringProperty()
  lower_title = ndb.ComputedProperty(lambda self: self.title.lower())
  artist = ndb.StringProperty()
  add_date = ndb.DateTimeProperty()
  isNew = ndb.BooleanProperty(default=False)
  songList = ndb.KeyProperty(repeated=True)
  cover_small = ndb.BlobKeyProperty()
  cover_large = ndb.BlobKeyProperty()

class Song(ndb.Model):
  title = ndb.StringProperty()
  artist = ndb.StringProperty()
  album = ndb.KeyProperty(kind=Album)

class Play(ndb.Model):
  song = ndb.KeyProperty(kind=Song)
  program = ndb.KeyProperty(kind=Program)
  play_date = ndb.DateTimeProperty()
  isNew = ndb.BooleanProperty() # TODO: Change from CamelCase to under_scores
  artist = ndb.StringProperty()

class ArtistName(ndb.Model):
  artist_name = ndb.StringProperty()
  lowercase_name = ndb.ComputedProperty(lambda self: self.artist_name.lower())
  search_name = ndb.ComputedProperty(lambda self: search_namify(self.artist_name))
  search_names = ndb.StringProperty(repeated=True)

class Psa(ndb.Model):
  desc = ndb.StringProperty()
  program = ndb.KeyProperty(kind=Program)
  play_date = ndb.DateTimeProperty()

class StationID(ndb.Model):
  program = ndb.KeyProperty(kind=Program)
  play_date = ndb.DateTimeProperty()

def search_namify(artist_name):
  SEARCH_IGNORE_PREFIXES = (
    "the ",
    "a ",
    "an ",)

  name = artist_name.lower()

  for prefix in SEARCH_IGNORE_PREFIXES:
    if name.startswith(prefix):
      name = name[len(prefix):]

  return name