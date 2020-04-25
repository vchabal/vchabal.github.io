(function () {
    
    // Elements
    let link = document.querySelector('a');
    let form = document.querySelector('form');
    let salt = document.querySelector('[placeholder=salt]');
    let password = document.querySelector('[placeholder=password]');

    // Reset clipboard and fields
    link.addEventListener('click', function () {
        setClipboard('');
        salt.value = '';
        password.value = '';
    });

    // Build key and encode it
    form.addEventListener('submit', function (e) {
        pbkdf2(password.value, salt.value).then(key => setClipboard(build(key)));
        salt.value = '';
        password.value = '';

        e.stopPropagation();
        return false;
    });

    /**
     * @param {string} baseKey
     * @param {string} salt
     * @returns {string} PBKDF2 key
     */
    async function pbkdf2 (baseKey, salt) {
        let encoder = new TextEncoder(),
            subtle = window.crypto.subtle;

        // Confgiration
        let alg = 'PBKDF2',
            hash = 'SHA-256',
            iterations = 100000,
            derivedKeyAlg = { name: 'AES-CTR', length: 256 };

        // SublteCrypto accepts data in given formats
        // Coverting base key and salt into stream of UTF-8 bytes
        let keyStream = encoder.encode(baseKey),
            saltStream = encoder.encode(salt),
            keyFormat = 'raw';

        // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
        let keyMaterial = await subtle.importKey(keyFormat, keyStream, alg, false, ['deriveKey']);

        // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
        let key = await subtle.deriveKey({ hash, iterations, name: alg, salt: saltStream }, keyMaterial, derivedKeyAlg, true, ['encrypt']);

        // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
        let rawKey = await subtle.exportKey('raw', key);
        
        // Return As HEX string
        return Array.prototype.map.call(new Uint8Array(rawKey), numToHex).join('');
    }

    /**
     * @param {number} num
     * @returns {string} Encoded HEX of length 2  
     */
    function numToHex (num) {
        return (num < 16 ? '0' : '') + num.toString(16);
    }

    /**
     * Put string to clipboard
     * @param {string} str 
     */
    function setClipboard (str) {
        window.navigator.permissions.query({name: 'clipboard-write'}).then(function(result) {
            if (result.state == 'granted' || result.state == 'prompt') {
                navigator.clipboard.writeText(str)
            }
        });
    }

    /**
     * @returns {string} ASCII CHARs from 32 to 126
     */
    function getASCII () {
        let asciiChars = [];
        for( let i = 32; i <= 126; i++ ) 
            asciiChars.push(String.fromCharCode(i));
        return asciiChars.join('');
    }

    /**
     * @param {string} str String
     * @returns {string} Generated password
     */
    function build (str) {
        let chars = getASCII(),
            password = [];
        let bi = BigInt('0x'+str),
            length = BigInt(chars.length);
        while (password.length < 16) {
            let c = chars.charAt(Number(bi % length));
            password.push(c);
            bi /= length;
        }

        return password.join('');
    }
})();