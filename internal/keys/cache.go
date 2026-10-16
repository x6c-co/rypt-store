package keys

import (
	"container/list"
	"sync"
	"time"
)

// cache holds unwrapped keys (core 5.6). Entries are fresh for ttl. After
// that they are kept up to maxStale longer for the serve_cached policy, and
// then dropped. The cache is bounded and evicts least-recently-used entries.
// Every eviction overwrites the key bytes. Callers always receive a copy, so
// an eviction never clears bytes that a caller is still using.
type cache struct {
	mu       sync.Mutex
	ttl      time.Duration
	maxStale time.Duration
	max      int
	now      func() time.Time
	items    map[string]*list.Element
	lru      *list.List // front = most recently used
	project  map[string]map[string]struct{}
}

type cacheEntry struct {
	id        string
	projectID string
	m         Material
	fetched   time.Time
}

func newCache(ttl, maxStale time.Duration, max int, now func() time.Time) *cache {
	return &cache{ttl: ttl, maxStale: maxStale, max: max, now: now,
		items: map[string]*list.Element{}, lru: list.New(), project: map[string]map[string]struct{}{}}
}

// get returns a copy of the key when it is fresh.
func (c *cache) get(id string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[id]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	age := c.now().Sub(e.fetched)
	if age > c.ttl+c.maxStale {
		c.remove(el)
		return nil, false
	}
	if age > c.ttl {
		return nil, false
	}
	c.lru.MoveToFront(el)
	return append([]byte(nil), e.m.b...), true
}

// getStale returns a copy of an expired entry still within maxStale.
func (c *cache) getStale(id string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[id]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if c.now().Sub(e.fetched) > c.ttl+c.maxStale {
		c.remove(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return append([]byte(nil), e.m.b...), true
}

// put stores a copy of b.
func (c *cache) put(id, projectID string, b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[id]; ok {
		c.remove(el)
	}
	e := &cacheEntry{id: id, projectID: projectID, m: Material{b: append([]byte(nil), b...)}, fetched: c.now()}
	c.items[id] = c.lru.PushFront(e)
	if projectID != "" {
		if c.project[projectID] == nil {
			c.project[projectID] = map[string]struct{}{}
		}
		c.project[projectID][id] = struct{}{}
	}
	for c.lru.Len() > c.max {
		c.remove(c.lru.Back())
	}
}

func (c *cache) evict(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[id]; ok {
		c.remove(el)
	}
}

// evictProject drops every key of a project (core 5.7 step 6).
func (c *cache) evictProject(projectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.project[projectID] {
		if el, ok := c.items[id]; ok {
			c.remove(el)
		}
	}
	delete(c.project, projectID)
}

func (c *cache) evictAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.lru.Len() > 0 {
		c.remove(c.lru.Back())
	}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

func (c *cache) remove(el *list.Element) {
	e := el.Value.(*cacheEntry)
	e.m.Clear()
	c.lru.Remove(el)
	delete(c.items, e.id)
	if ids := c.project[e.projectID]; ids != nil {
		delete(ids, e.id)
		if len(ids) == 0 {
			delete(c.project, e.projectID)
		}
	}
}
