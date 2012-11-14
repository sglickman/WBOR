from base_models import QueryCache

from google.appengine.ext import db, ndb

import logging

# Children have a cache of most-recently added elements.
# This is like LastCacheable, but does not include any time data
class NewCacheable(object):
  NEW = None

  @classmethod
  def add_to_new_cache(cls, key):
    cached = QueryCache.fetch(cls.NEW)
    cached.prepend(key)
    cached.save()

  @classmethod
  def purge_from_new_cache(cls, key):
    cached = QueryCache.fetch(cls.NEW)
    try:
      cached.remove(key)
      cached.save()
    except:
      pass

  @classmethod
  def get_new(cls, num=-1, keys_only=False):
    if num != -1 and num < 1:
      return None

    only_one = False
    if num == -1:
      only_one = True
      num = 1

    cached = QueryCache.fetch(cls.NEW)

    new_objs = []
    cached_keys = []
    if cached.need_fetch(num):
      try:
        num_to_fetch = num - len(cached)
        new_objs,cursor,more = cls.get(order=(-ndb.Model.key),
          num=num_to_fetch, page=True, cursor=cached.cursor)
        cached_keys = tuple(cached.results)
        cached.extend_by([obj.key for obj in new_objs],
                         cursor=cursor, more=more)
      except db.BadRequestError:
        new_objs,cursor,more = cls.get(order=(-ndb.Model.key),
          num=num, page=True, cursor=None)
        cached_keys = tuple()
        cached.set([obj.key for obj in new_objs],
                   cursor=cursor, more=more)
      cached.save()
    else:
      cached_keys = tuple(cached.results)

    if not cached:
      return [] if not only_one else None

    if keys_only:
      return cached.results[0] if only_one else cached.results[:num]
    else:
      if only_one:
        return cls.get(cached.results[0])
      return (cls.get(cached_keys) + new_objs)[:num]