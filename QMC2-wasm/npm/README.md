# QMC2-Crypto

This file is part of [qmc2][qmc2] project, licensed under the
[MIT License][license].

For usage, please see the [demo source][demo_src].

## Legacy

Default export is the legacy build (pure JS), which does not require WASM.

```js
const QMCCryptoModule = require('@jixun/qmc2-crypto'); // js
import QMCCryptoModule from '@jixun/qmc2-crypto'; // ts with typing

// or:

const QMCCryptoModule = require('@jixun/qmc2-crypto/QMC2-legacy'); // js
import QMCCryptoModule from '@jixun/qmc2-crypto/QMC2-legacy'; // ts with typing
```

## WASM

WwbAssembly version. Uses external web assembly file.

You'll need to place the file `node_modules/@jixun/qmc2-crypto/QMC2-wasm.wasm`
to the same directory of your `app.js`.

```js
const QMCCryptoModule = require('@jixun/qmc2-crypto/QMC2-wasm'); // js
import QMCCryptoModule from '@jixun/qmc2-crypto/QMC2-wasm'; // ts with typing

QMCCryptoModule().then(QMCCrypto => {
	// Your code here.
});
```

## WASM-Bundle

Similar to WASM, but with WASM binary embedded to the JavaScript file.

```js
const QMCCryptoModule = require('@jixun/qmc2-crypto/QMC2-wasm-bundle'); // cjs
import QMCCryptoModule from '@jixun/qmc2-crypto/QMC2-wasm-bundle'; // ts

QMCCryptoModule().then(QMCCrypto => {
	// Your code here.
});
```

[qmc2]: https://github.com/jixunmoe/qmc2/
[license]: https://github.com/jixunmoe/qmc2/blob/main/LICENSE
[demo_src]: https://jixunmoe.github.io/qmc2/source.html
