(function () {
    
    // Elements
    let form = document.querySelector('form');
    let salt = document.querySelector('[type=text]');
    let password = document.querySelector('[type=password]');

    // Reset clipboard and fields
    form.addEventListener('reset', function () {
        setClipboard('');
    });

    // Build key and encode it
    form.addEventListener('submit', function (e) {
        e.stopPropagation();
        e.preventDefault();

        let config = { len: 16, az: 1, num: 1, sp: 1 };
        let input = salt.value.trim().split(/\s+/);
        let saltStr = input.shift();
        
        // Parsing parameters from input - len16 az1 num1 sp1
        input.reduce((o, param) => { setParam(o, param); return o; }, config);

        // Run PBKDF2 and put result into clipboard
        pbkdf2(password.value, saltStr)
            .then(key => build(key, config.len, config.az, config.num, config.sp))
            .then(password => setClipboard(password));
        
        salt.value = '';
        password.value = '';

        return false;
    });

    /**
     * Adds parameter to the object
     * @param {object} config Configuration object 
     * @param {string} param len16, az0, num0, sp0, ...
     */
    function setParam(config, param) {
        let value = param.replace(/^[^\d]+/, '');
        let prop = param.substr(0, param.length - value.length);
        config[prop] = parseInt(value);
    }

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
     * @returns {Array<string>} ASCII CHARs from 32 to 126
     */
    function getASCII () {
        let asciiChars = [];
        for( let i = 32; i <= 126; i++ ) 
            asciiChars.push(String.fromCharCode(i));
        return asciiChars;
    }

    /**
     * @param {string} str String
     * @param {number} length Password length
     * @param {number} azChars Count of a-z characters
     * @param {number} numChars Count of 0-9 characters
     * @param {number} specialChars Count of special characters
     * @returns {string} Generated password
     */
    function build (str, length, azChars, numChars, specialChars) {
        let chars = getASCII(),
            password = [];

        let bi = BigInt('0x'+str),
            charsLength = BigInt(chars.length);

        while (password.length < length) {
            let c = chars[Number(bi % charsLength)];
            password.push(c);
            bi /= charsLength;
        }

        // lower + UPPER >= count
        let azLowerChars = Math.round(azChars/2); 
            configs = [
                { regex: /[a-z]/, required: azLowerChars }, 
                { regex: /[A-Z]/, required: azChars - azLowerChars }, 
                { regex: /\d/, required: numChars }, 
                { regex: /\W/, required: specialChars }];

        for (let config of configs) {
            let currentCnt = password.filter(i => config.regex.test(i)).length;
            let requiredCnt = config.required;

            if (currentCnt >= requiredCnt) 
                continue;
            
            let subchars = chars.filter(i => config.regex.test(i)),
                subcharsLength = BigInt(subchars.length);

            for (; currentCnt < requiredCnt; currentCnt++) {
                let c = subchars[Number(bi % subcharsLength)];
                bi /= subcharsLength;

                let insertPlaces = BigInt(password.length + 1);
                let i = Number(bi % insertPlaces);
                bi /= insertPlaces;

                password.splice(i, 0, c);
            }
        }

        return password.join('');
    }
})();