// TrojanHorse.js Service Worker
// Provides offline capabilities and background threat monitoring

const CACHE_NAME = 'trojanhorse-v1';
const STATIC_CACHE = 'trojanhorse-static-v1';
const DYNAMIC_CACHE = 'trojanhorse-dynamic-v1';

// Files to cache for offline use
const STATIC_FILES = [
  '/',
  '/index.html',
  '/production-integration.html',
  '/simple-static-site.html',
  'https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js'
];

// Install event - cache static files
self.addEventListener('install', event => {
  console.log('TrojanHorse SW: Installing...');
  
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('TrojanHorse SW: Caching static files');
        return cache.addAll(STATIC_FILES);
      })
      .then(() => {
        console.log('TrojanHorse SW: Static files cached');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('TrojanHorse SW: Failed to cache static files:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('TrojanHorse SW: Activating...');
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
              console.log('TrojanHorse SW: Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('TrojanHorse SW: Activated');
        return self.clients.claim();
      })
  );
});

// Fetch event - serve from cache with network fallback
self.addEventListener('fetch', event => {
  const { request } = event;
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Handle API requests
  if (request.url.includes('/api/')) {
    event.respondWith(handleApiRequest(request));
    return;
  }
  
  // Handle static files
  if (STATIC_FILES.some(file => request.url.includes(file))) {
    event.respondWith(
      caches.match(request)
        .then(response => {
          return response || fetch(request);
        })
        .catch(() => {
          // Return offline page if available
          return caches.match('/offline.html');
        })
    );
    return;
  }
  
  // Handle dynamic content with cache-first strategy
  event.respondWith(
    caches.match(request)
      .then(response => {
        if (response) {
          // Serve from cache
          return response;
        }
        
        // Fetch from network and cache
        return fetch(request)
          .then(networkResponse => {
            // Don't cache non-successful responses
            if (!networkResponse || networkResponse.status !== 200) {
              return networkResponse;
            }
            
            // Clone response for caching
            const responseClone = networkResponse.clone();
            
            caches.open(DYNAMIC_CACHE)
              .then(cache => {
                cache.put(request, responseClone);
              });
            
            return networkResponse;
          })
          .catch(() => {
            // Return cached version or offline message
            return new Response(
              JSON.stringify({
                error: 'Network unavailable',
                offline: true,
                timestamp: new Date().toISOString()
              }),
              {
                status: 503,
                headers: { 'Content-Type': 'application/json' }
              }
            );
          });
      })
  );
});

// Handle API requests with offline support
async function handleApiRequest(request) {
  try {
    // Try network first
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      // Cache successful responses
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
    
  } catch (error) {
    console.log('TrojanHorse SW: Network failed, checking cache...');
    
    // Try cache
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      // Add offline indicator to cached response
      const data = await cachedResponse.json();
      data._offline = true;
      data._cachedAt = new Date().toISOString();
      
      return new Response(JSON.stringify(data), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Return offline response
    return new Response(
      JSON.stringify({
        error: 'Service unavailable offline',
        offline: true,
        message: 'This feature requires an internet connection'
      }),
      {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// Background sync for offline threat checks
self.addEventListener('sync', event => {
  console.log('TrojanHorse SW: Background sync triggered');
  
  if (event.tag === 'threat-check') {
    event.waitUntil(processPendingThreatChecks());
  }
});

// Process queued threat checks when back online
async function processPendingThreatChecks() {
  try {
    // Get pending checks from IndexedDB
    const pendingChecks = await getPendingChecks();
    
    for (const check of pendingChecks) {
      try {
        const response = await fetch('/api/threat-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(check.data)
        });
        
        if (response.ok) {
          const result = await response.json();
          
          // Notify all clients about the result
          const clients = await self.clients.matchAll();
          clients.forEach(client => {
            client.postMessage({
              type: 'BACKGROUND_CHECK_COMPLETE',
              checkId: check.id,
              result: result
            });
          });
          
          // Remove from pending queue
          await removePendingCheck(check.id);
        }
      } catch (error) {
        console.error('TrojanHorse SW: Failed to process check:', error);
      }
    }
  } catch (error) {
    console.error('TrojanHorse SW: Background sync failed:', error);
  }
}

// Message handling for communication with main thread
self.addEventListener('message', event => {
  const { type, data } = event.data;
  
  switch (type) {
    case 'QUEUE_THREAT_CHECK':
      queueThreatCheck(data)
        .then(() => {
          event.ports[0].postMessage({ success: true });
        })
        .catch(error => {
          event.ports[0].postMessage({ error: error.message });
        });
      break;
      
    case 'GET_CACHE_STATUS':
      getCacheStatus()
        .then(status => {
          event.ports[0].postMessage({ status });
        });
      break;
      
    case 'CLEAR_CACHE':
      clearAllCaches()
        .then(() => {
          event.ports[0].postMessage({ success: true });
        });
      break;
  }
});

// Queue threat check for background processing
async function queueThreatCheck(checkData) {
  const check = {
    id: generateId(),
    data: checkData,
    timestamp: Date.now()
  };
  
  // Store in IndexedDB for persistence
  await storePendingCheck(check);
  
  // Register for background sync
  await self.registration.sync.register('threat-check');
}

// IndexedDB helpers for offline storage
async function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('TrojanHorseDB', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = event => {
      const db = event.target.result;
      
      if (!db.objectStoreNames.contains('pendingChecks')) {
        db.createObjectStore('pendingChecks', { keyPath: 'id' });
      }
      
      if (!db.objectStoreNames.contains('threatCache')) {
        const store = db.createObjectStore('threatCache', { keyPath: 'key' });
        store.createIndex('timestamp', 'timestamp');
      }
    };
  });
}

async function storePendingCheck(check) {
  const db = await openDB();
  const transaction = db.transaction(['pendingChecks'], 'readwrite');
  const store = transaction.objectStore('pendingChecks');
  
  return new Promise((resolve, reject) => {
    const request = store.add(check);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

async function getPendingChecks() {
  const db = await openDB();
  const transaction = db.transaction(['pendingChecks'], 'readonly');
  const store = transaction.objectStore('pendingChecks');
  
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

async function removePendingCheck(id) {
  const db = await openDB();
  const transaction = db.transaction(['pendingChecks'], 'readwrite');
  const store = transaction.objectStore('pendingChecks');
  
  return new Promise((resolve, reject) => {
    const request = store.delete(id);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

// Cache management
async function getCacheStatus() {
  const cacheNames = await caches.keys();
  const status = {};
  
  for (const cacheName of cacheNames) {
    const cache = await caches.open(cacheName);
    const keys = await cache.keys();
    status[cacheName] = {
      size: keys.length,
      entries: keys.map(key => key.url)
    };
  }
  
  return status;
}

async function clearAllCaches() {
  const cacheNames = await caches.keys();
  return Promise.all(
    cacheNames.map(cacheName => caches.delete(cacheName))
  );
}

// Utility functions
function generateId() {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

// Periodic cleanup of old cache entries
setInterval(async () => {
  try {
    const db = await openDB();
    const transaction = db.transaction(['threatCache'], 'readwrite');
    const store = transaction.objectStore('threatCache');
    const index = store.index('timestamp');
    
    // Remove entries older than 24 hours
    const cutoff = Date.now() - (24 * 60 * 60 * 1000);
    const range = IDBKeyRange.upperBound(cutoff);
    
    const request = index.openCursor(range);
    request.onsuccess = event => {
      const cursor = event.target.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      }
    };
  } catch (error) {
    console.error('TrojanHorse SW: Cache cleanup failed:', error);
  }
}, 60 * 60 * 1000); // Run every hour

console.log('TrojanHorse SW: Service Worker loaded');