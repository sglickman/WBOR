from base_models import SetQueryCache

def prefixize(term, sep=None):
  term = term.strip().lower()
  prefixes = [term[:i+1] for i in range(len(term))]
  # TODO: Improve this.
  return prefixes

def add_to_autocomplete_caches(key, cachekey_base, prefixes):
  for cache in [SetQueryCache.fetch(cachekey_base % prefix) for
                prefix in prefixes]:
    cache.add(key)
    cache.save()

def purge_from_autocomplete_caches(key, cachekey_base, prefixes):
  for cache in [SetQueryCache.fetch(cachekey_base % prefix) for
                prefix in prefixes]:
    try:
      cache.remove(key)
      cache.save()
    except KeyError:
      pass