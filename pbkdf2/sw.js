const CACHE_NAME = 'pbkdf2-v8';
const CACHE_FILES = [
    './',
    'index.html',
    'pbkdf2.js',
    'icon-v2.png'
]

self.addEventListener('install', event =>
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Adding files:', CACHE_FILES);
                return cache.addAll(CACHE_FILES);
            })
    )
);

self.addEventListener('activate', event => 
    event.waitUntil(
        caches.keys().then(cacheNames =>
            Promise.all(
                cacheNames.filter(cacheName => {
                    let delteCache = /^pbkdf2/i.test(cacheName) && cacheName !== CACHE_NAME;
                    if (!delteCache) console.log('Cache won\'t be deleted:', cacheName);
                    return delteCache;
                }).map(cacheName => {
                    console.log('Deleting cache:', cacheName);
                    return caches.delete(cacheName);
                })
            )
        )
    )
);

self.addEventListener('fetch', event =>
    event.respondWith(
        caches.open(CACHE_NAME).then(cache =>
            cache.match(event.request).then(response => {
                var fetchPromise = fetch(event.request).then(networkResponse => {
                    cache.put(event.request, networkResponse.clone());
                    return networkResponse;
                });
                return response || fetchPromise;
            })
        )
    )
);