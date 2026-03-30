// Dilithion Wallet Service Worker
// Caches wallet assets for offline access (keys stay in IndexedDB regardless)

const CACHE_NAME = 'dilithion-wallet-v3';

// Core assets to cache for offline wallet access
const CORE_ASSETS = [
    '/wallet.html',
    '/js/dilithium.js',
    '/js/dilithium.wasm',
    '/js/dilithium-crypto.js',
    '/js/local-wallet.js',
    '/js/connection-manager.js',
    '/js/transaction-builder.js',
    '/dilithion-logo-256.png',
    '/favicon.ico'
];

// Install: cache core assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            console.log('[SW] Caching core assets');
            return cache.addAll(CORE_ASSETS);
        }).then(() => self.skipWaiting())
    );
});

// Activate: clean old caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch: network-first for API calls, cache-first for static assets
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // API calls and external resources: always go to network
    if (url.pathname.startsWith('/api/') ||
        url.hostname !== self.location.hostname ||
        event.request.method !== 'GET') {
        return;  // Let browser handle normally
    }

    // Static assets: cache-first, fallback to network
    event.respondWith(
        caches.match(event.request).then(cached => {
            if (cached) {
                // Return cached version, but also update cache in background
                fetch(event.request).then(response => {
                    if (response.ok) {
                        caches.open(CACHE_NAME).then(cache => {
                            cache.put(event.request, response);
                        });
                    }
                }).catch(() => {});
                return cached;
            }

            // Not cached: fetch from network and cache
            return fetch(event.request).then(response => {
                if (response.ok) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => {
                        cache.put(event.request, clone);
                    });
                }
                return response;
            });
        })
    );
});
