#!/usr/bin/env python
#
# Author: Harrison Chapman
# This file contains the Play model, and auxiliary functions.
#  A Play object corresponds to a row in the Play table in the
# datastore, which itself refers to a charted song by a Dj.


from __future__ import with_statement

# GAE Imports
from google.appengine.ext import db, ndb

from _raw_models import Play as RawPlay
from _raw_models import Psa as RawPsa
from _raw_models import StationID as RawStationID

# Local module imports
from base_models import *
from tracks import Album, Song
from dj import Dj
from program import Program

# Global python imports
import logging
import datetime
import logging
import itertools
import random

# Here's the idea behind last-caching:
# TODO: write description of last-caching'

class LastCachedModel(CachedModel):
  '''A model for which there is a global cache of "Last instances",
  e.g. a cache of all recently charted songs (see the Play class)'''

  LAST = None #Important that children overwrite this to avoid clashes
  LAST_ORDER = 1 #One of 1, -1
  LAST_ORDERBY = None #Get last X based on this ordering

  @classmethod
  def get_last(cls, num=-1, keys_only=False,
               before=None, after=None):
    if num != -1 and num < 1:
      return None

    only_one = False
    if num == -1:
      only_one = True
      num = 1

    cached = SortedQueryCache.fetch(cls.LAST)

    last = []
    cached_keys = []
    if cached.need_fetch(num):
      try:
        num_to_fetch = num - len(cached)
        last, cursor, more = cls.get(num=num_to_fetch,
                                     order=cls.LAST_ORDERBY,
                                     page=True, cursor=cached.cursor)
        cached_keys = cached.results
        cached.extend_by([(obj.key, obj._orderby) for obj in last],
                         cursor=cursor, more=more)
      except db.BadRequestError:
        last, cursor, more = cls.get(num=num, order=cls.LAST_ORDERBY,
                                 page=True, cursor=None)
        cached_keys = []
        cached.set([(obj.key, obj._orderby) for obj in last],
                   cursor=cursor, more=more)

      cached.save()
    else:
      cached_keys = cached.results

    if not cached:
      return []

    if keys_only:
      if only_one:
        return cached.results[-1]

      return cached.results
    else:
      if only_one:
        return cls.get(cached.results[-1])

      rslt = cls.get(cached_keys) + last
      return rslt

  @classmethod
  def get_last_keys(cls, num=-1, before=None, after=None):
    return cls.get_last(num=num, before=before, after=after, keys_only=True)

  # Method to add a new element to the lastcache for this class
  @classmethod
  def add_to_last_cache(cls, obj):
    cached = cls.get_cached_query(cls.LAST)
    cached.ordered_unique_insert(obj.key, obj._orderby)
    cached.save()

  # Utility method so that a last-cacheable entry knows how to
  # lastcache itself.
  def add_own_last_cache(self):
    self.add_to_last_cache(self.key, orderby=self._orderby)

class Play(LastCachedModel):
  _RAW = RawPlay
  _RAWKIND = "Play"

  '''A Play is an (entirely) immutable datastore object which represents
  a charted song
  '''
  LAST = "@last_plays" # Tuple of last_plays_list, db_count
  LAST_ORDER = -1 # Sort from most recent backwards
  LAST_ORDERBY = (_RAW.play_date,) # How plays should be ordered in last cache
  SHOW_LAST = "last_plays_show%s" #possibly keep with show instead

  TOP_SONGS = "@top_songs_before%s_after%s"
  TOP_ALBUMS = "@top_albums_before%s_after%s"

  @staticmethod
  def _orderby(raw):
    return raw.play_date

  @property
  def program_key(self):
    return self.raw.program
  @property
  def song_key(self):
    return self.raw.song

  ## Properties
  @property
  def song(self):
    return Song.get(self.song_key)
  @property
  def program(self):
    return Program.get(self.program_key)
  @property
  def play_date(self):
    return self.raw.play_date
  @property
  def is_new(self):
    return self.raw.isNew
  @property
  def artist(self):
    return self.raw.artist

  def to_json(self):
    return {
      'key': str_or_none(self.key),
      'song_key': str_or_none(self.song_key),
      'program_key': str_or_none(self.program_key),
      'play_date': time.mktime(self.play_date.utctimetuple()) * 1000
    }

  def __init__(self, raw=None, song=None, program=None, artist=None,
               is_new=None, play_date=None,
               parent=None,
               is_fresh=False, **kwds):
    if raw is not None:
      super(Play, self).__init__(raw=raw)
    else:
      if parent is None:
        parent = program

      if play_date is None:
        play_date = datetime.datetime.now()

      super(Play, self).__init__(parent=parent,
                                 song=as_key(song),
                                 program=as_key(program),
                                 artist=artist,
                                 play_date=play_date,
                                 isNew=is_new, **kwds)

    self.is_fresh = is_fresh

  @classmethod
  def new(cls, song, program, artist, is_fresh=True, **kwds):
    return cls(song=song, program=program, artist=artist,
               is_fresh=is_fresh)

  def add_to_cache(self):
    super(Play, self).add_to_cache()
    try:
      if self.is_fresh:
        self.add_own_last_cache()
    except AttributeError:
      pass
    return self

  def purge_from_cache(self):
    super(Play, self).purge_from_cache()

    return self

  @classmethod
  def get(cls, keys=None, before=None, after=None, is_new=None, order=None,
          num=-1, page=False, cursor=None, one_key=False):
    if keys is not None:
      return super(Play, cls).get(keys=keys,
                                  one_key=one_key)

    keys = cls.get_key(before=before, after=after,
                       is_new=is_new, order=order, num=num,
                       page=page, cursor=cursor)
    if page:
      keys, cursor, more = keys

    if keys is not None:
      if page:
        return (cls.get(keys=keys),
                cursor, more)
      else:
        return cls.get(keys=keys)
    return None

  @classmethod
  def get_key(cls, before=None, after=None, is_new=None,
             order=None, num=-1, page=False, cursor=None):
    query = cls._RAW.query()

    if is_new is not None:
      query = query.filter(RawPlay.isNew == is_new)
    if after is not None:
      query = query.filter(RawPlay.play_date >=
                           datetime.datetime.combine(after, datetime.time()))
    if before is not None:
      query = query.filter(RawPlay.play_date <=
                           datetime.datetime.combine(before, datetime.time()))
    if order is not None:
      query = query.order(*order)

    if num == -1:
      return query.get(keys_only=True, start_cursor=cursor)
    elif not page:
      return query.fetch(num, keys_only=True, start_cursor=cursor)
    else:
      return query.fetch_page(num, keys_only=True, start_cursor=cursor)

  def put(self):
    key = super(Play, self).put()

    if key and self.is_fresh and self.program:
      program = self.program
      program.update_top_artists(self.artist)
      program.put()

    return key

  @classmethod
  def delete_key(cls, key, program=None):
    if program is not None:
      pass # Inform parent program that we're deleting this play'

    super(Play, cls).delete_key(key=key)

  # We override the get_last method to use, e.g., the parent program
  # in our queries
  @classmethod
  def get_last(cls, num=-1, keys_only=False,
               program=None, before=None, after=None):
    # We may want to get the last plays of a specific program
    # Otherwise, use the already defined super method.
    if program is None:
      return super(Play, cls).get_last(num=num, keys_only=keys_only,
                                       before=before, after=after)

    # TODO: Pass other parameters to program's method
    if program is not None:
      program = Program.as_object(program)
      return program.get_last_plays(num=num)
    return None if num == -1 else []

  @classmethod
  def get_last_keys(cls, num=-1, program=None, before=None, after=None):
    return cls.get_last(num=num, keys_only=True,
                        program=program, before=before, after=after)

  ## Custom queries pertaining to plays

  # Get top songs and albums
  # returns a tuple(songs, albums)
  @classmethod
  def get_top(cls, after=None, before=None,
              song_num=10, album_num=10, keys_only=False):
    # Sanitize our range dates. Dates instead of times make caching
    # more convenient, and I don't even think we can ask for times
    # anyway
    if before is None:
      before = datetime.date.today() + datetime.timedelta(days=1)
    else:
      if isinstance(before, datetime.datetime):
        before = before.date()
      before += datetime.timedelta(days=1)
      if after is None:
        after = datetime.date.today() - datetime.timedelta(days=6)
      elif isinstance(after, datetime.datetime):
          after = after.date()

    cached_songs = cls.get_cached_query(cls.TOP_SONGS, before, after)
    cached_albums = cls.get_cached_query(cls.TOP_ALBUMS, before, after)

    # If our caches exist and are sufficient
    if not (cached_songs is None or
            cached_songs.need_fetch(song_num) or
            cached_albums is None or
            cached_albums.need_fetch(album_num)):
      songs = cached_songs.results
      albums = cached_albums.results

    else:
      new_plays = cls.get(before=before, after=after, is_new=True, num=1000)
      songs = {}
      albums = {}

      for play in new_plays:
        song_key = play.song_key
        if song_key in songs:
          songs[song_key] += 1
        else:
          songs[song_key] = 1
        if play.song_key is not None and play.song.album_key is not None:
          album_key = play.song.album_key
          if album_key in albums:
            albums[album_key] += 1
          else:
            albums[album_key] = 1

      songs = songs.items()
      albums = albums.items()

    if not keys_only:
      songs = [(Song.get(song), count) for song,count in songs]
    if not keys_only:
      albums = [(Album.get(album), count) for album,count in albums]

    songs = sorted(songs, key=lambda x: x[1], reverse=True)[:song_num]
    albums = sorted(albums, key=lambda x: x[1], reverse=True)[:album_num]

    cached_songs

    return (songs, albums)


class Psa(LastCachedModel):
  _RAW = RawPsa
  _RAWKIND = "Psa"

  LAST = "@@last_psas" # Tuple of last_plays_list, db_count
  LAST_ORDER = -1 # Sort from most recent backwards
  LAST_ORDERBY =  -_RAW.play_date # How plays should be ordered in last cache
  SHOW_LAST = "last_psas_show%s" #possibly keep with show instead
  ENTRY = "psa_key%s"

  @classmethod
  def new(cls, desc, program, play_date=None,
          parent=None, key_name=None, **kwds):
    if parent is None:
      parent = program

    if play_date is None:
      play_date = datetime.datetime.now()

    psa = cls(parent=parent, key_name=key_name,
               desc=desc, program=program, play_date=play_date, **kwds)

    psa.is_fresh = True

    return psa

  def add_to_cache(self):
    super(Psa, self).add_to_cache()
    try:
      if self.is_fresh:
        self.add_own_last_cache()
    except AttributeError:
      pass
    return self

  @classmethod
  def get(cls, keys=None, before=None, after=None, order=None,
          num=-1, use_datastore=True, one_key=False):
    if keys is not None:
      return super(Psa, cls).get(keys=keys,
                                 use_datastore=use_datastore,
                                 one_key=one_key)

    keys = cls.get_key(before=before, after=after,
                       order=order, num=num)
    if keys is not None:
      return cls.get(keys=keys, use_datastore=use_datastore)
    return None

  @classmethod
  def get_key(cls, before=None, after=None,
             order=None, num=-1):
    query = Psa.all(keys_only=True)

    if after is not None:
      query = query.filter("play_date >=", after)
    if before is not None:
      query = query.filter("play_date <=", before)
    if order is not None:
      query.order(*order)

    if num == -1:
      return query.get()
    return query.fetch(num)

  def put(self):
    super(Psa, self).put()

  @classmethod
  def delete_key(cls, key, program=None):
    if program is not None:
      pass # Inform parent program that we're deleting this play'

    super(Psa, cls).delete_key(key=key)

  # We override the get_last method to use, e.g., the parent program
  # in our queries
  @classmethod
  def get_last(cls, num=-1, keys_only=False,
               program=None, before=None, after=None):
    # We may want to get the last psas of a specific program
    # Otherwise, use the already defined super method.
    if program is None:
      return super(Psa, cls).get_last(num=num, keys_only=keys_only,
                                       before=before, after=after)

    # TODO: Pass other parameters to program's method
    program = Program.as_object(program)
    if program is not None:
      return program.get_last_psas(num=num)
    return None if num == -1 else []

  @classmethod
  def get_last_keys(cls, num=-1, program=None, before=None, after=None):
    return cls.get_last(num=num, keys_only=True,
                        program=program, before=before, after=after)

class StationID(object):
  pass