
        //加载了基础功能补充代码块
        window.Internal = Internal || {};
        (function() {
            'use strict';

            var crypto = window.crypto;

            if (!crypto || !crypto.subtle || typeof crypto.getRandomValues !== 'function') {
                throw new Error('WebCrypto not found');
            }

            Internal.crypto = {
                getRandomBytes: function(size) {
                    var array = new Uint8Array(size);
                    crypto.getRandomValues(array);
                    return array.buffer;
                },
                encrypt: function(key, data, iv) {
                    return crypto.subtle.importKey('raw', key, {name: 'AES-CBC'}, false, ['encrypt']).then(function(key) {
                        return crypto.subtle.encrypt({name: 'AES-CBC', iv: new Uint8Array(iv)}, key, data);
                    });
                },
                decrypt: function(key, data, iv) {
                    return crypto.subtle.importKey('raw', key, {name: 'AES-CBC'}, false, ['decrypt']).then(function(key) {
                        return crypto.subtle.decrypt({name: 'AES-CBC', iv: new Uint8Array(iv)}, key, data);
                    });
                },
                sign: function(key, data) {
                    return crypto.subtle.importKey('raw', key, {name: 'HMAC', hash: {name: 'SHA-256'}}, false, ['sign']).then(function(key) {
                        return crypto.subtle.sign( {name: 'HMAC', hash: 'SHA-256'}, key, data);
                    });
                },

                hash: function(data) {
                    return crypto.subtle.digest({name: 'SHA-512'}, data);
                },

                HKDF: function(input, salt, info) {
                    // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
                    // TODO: We dont always need the third chunk, we might skip it
                    return Internal.crypto.sign(salt, input).then(function(PRK) {
                        var infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32);
                        var infoArray = new Uint8Array(infoBuffer);
                        infoArray.set(new Uint8Array(info), 32);
                        infoArray[infoArray.length - 1] = 1;
                        return Internal.crypto.sign(PRK, infoBuffer.slice(32)).then(function(T1) {
                            infoArray.set(new Uint8Array(T1));
                            infoArray[infoArray.length - 1] = 2;
                            return Internal.crypto.sign(PRK, infoBuffer).then(function(T2) {
                                infoArray.set(new Uint8Array(T2));
                                infoArray[infoArray.length - 1] = 3;
                                return Internal.crypto.sign(PRK, infoBuffer).then(function(T3) {
                                    return [ T1, T2, T3 ];
                                });
                            });
                        });
                    });
                },

                // Curve 25519 crypto
                createKeyPair: function(privKey) {
                    if (privKey === undefined) {
                        privKey = Internal.crypto.getRandomBytes(32);
                    }
                    return Internal.Curve.async.createKeyPair(privKey);
                },
                ECDHE: function(pubKey, privKey) {
                    return Internal.Curve.async.ECDHE(pubKey, privKey);
                },
                Ed25519Sign: function(privKey, message) {
                    return Internal.Curve.async.Ed25519Sign(privKey, message);
                },
                Ed25519Verify: function(pubKey, msg, sig) {
                    return Internal.Curve.async.Ed25519Verify(pubKey, msg, sig);
                }
            };

            // HKDF for TextSecure has a bit of additional handling - salts always end up being 32 bytes
            Internal.HKDF = function(input, salt, info) {
                if (salt.byteLength != 32) {
                    throw new Error("Got salt of incorrect length");
                }

                return Internal.crypto.HKDF(input, salt,  util.toArrayBuffer(info));
            };

            Internal.verifyMAC = function(data, key, mac, length) {
                return Internal.crypto.sign(key, data).then(function(calculated_mac) {
                    if (mac.byteLength != length  || calculated_mac.byteLength < length) {
                        throw new Error("Bad MAC length");
                    }
                    var a = new Uint8Array(calculated_mac);
                    var b = new Uint8Array(mac);
                    var result = 0;
                    for (var i=0; i < mac.byteLength; ++i) {
                        result = result | (a[i] ^ b[i]);
                    }
                    if (result !== 0) {
                        throw new Error("Bad MAC");
                    }
                });
            };

            libsignal.HKDF = {
                deriveSecrets: function(input, salt, info) {
                    return Internal.HKDF(input, salt, info);
                }
            };

            libsignal.crypto = {
                encrypt: function(key, data, iv) {
                    return Internal.crypto.encrypt(key, data, iv);
                },
                decrypt: function(key, data, iv) {
                    return Internal.crypto.decrypt(key, data, iv);
                },
                calculateMAC: function(key, data) {
                    return Internal.crypto.sign(key, data);
                },
                verifyMAC: function(data, key, mac, length) {
                    return Internal.verifyMAC(data, key, mac, length);
                },
                getRandomBytes: function(size) {
                    return Internal.crypto.getRandomBytes(size);
                }
            };

        })();
        (function() {
            'use strict';

            function validatePrivKey(privKey) {
                if (privKey === undefined || !(privKey instanceof ArrayBuffer) || privKey.byteLength != 32) {
                    throw new Error("Invalid private key");
                }
            }
            function validatePubKeyFormat(pubKey) {
                if (pubKey === undefined || ((pubKey.byteLength != 33 || new Uint8Array(pubKey)[0] != 5) && pubKey.byteLength != 32)) {
                    throw new Error("Invalid public key");
                }
                if (pubKey.byteLength == 33) {
                    return pubKey.slice(1);
                } else {
                    console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
                    return pubKey;
                }
            }

            function processKeys(raw_keys) {
                // prepend version byte
                var origPub = new Uint8Array(raw_keys.pubKey);
                var pub = new Uint8Array(33);
                pub.set(origPub, 1);
                pub[0] = 5;

                return { pubKey: pub.buffer, privKey: raw_keys.privKey };
            }

            function wrapCurve25519(curve25519) {
                return {
                    // Curve 25519 crypto
                    createKeyPair: function(privKey) {
                        validatePrivKey(privKey);
                        var raw_keys = curve25519.keyPair(privKey);
                        if (raw_keys instanceof Promise) {
                            return raw_keys.then(processKeys);
                        } else {
                            return processKeys(raw_keys);
                        }
                    },
                    ECDHE: function(pubKey, privKey) {
                        pubKey = validatePubKeyFormat(pubKey);
                        validatePrivKey(privKey);

                        if (pubKey === undefined || pubKey.byteLength != 32) {
                            throw new Error("Invalid public key");
                        }

                        return curve25519.sharedSecret(pubKey, privKey);
                    },
                    Ed25519Sign: function(privKey, message) {
                        validatePrivKey(privKey);

                        if (message === undefined) {
                            throw new Error("Invalid message");
                        }

                        return curve25519.sign(privKey, message);
                    },
                    Ed25519Verify: function(pubKey, msg, sig) {
                        pubKey = validatePubKeyFormat(pubKey);

                        if (pubKey === undefined || pubKey.byteLength != 32) {
                            throw new Error("Invalid public key");
                        }

                        if (msg === undefined) {
                            throw new Error("Invalid message");
                        }

                        if (sig === undefined || sig.byteLength != 64) {
                            throw new Error("Invalid signature");
                        }

                        return curve25519.verify(pubKey, msg, sig);
                    }
                };
            }

            Internal.Curve       = wrapCurve25519(Internal.curve25519);
            Internal.Curve.async = wrapCurve25519(Internal.curve25519_async);

            function wrapCurve(curve){
                return {
                    generateKeyPair: function() {
                        var privKey = Internal.crypto.getRandomBytes(32);
                        return curve.createKeyPair(privKey);
                    },
                    createKeyPair: function(privKey) {
                        return curve.createKeyPair(privKey);
                    },
                    calculateAgreement: function(pubKey, privKey) {
                        return curve.ECDHE(pubKey, privKey);
                    },
                    verifySignature: function(pubKey, msg, sig) {
                        return curve.Ed25519Verify(pubKey, msg, sig);
                    },
                    calculateSignature: function(privKey, message) {
                        return curve.Ed25519Sign(privKey, message);
                    }
                };
            }

            libsignal.Curve       = wrapCurve(Internal.Curve);
            libsignal.Curve.async = wrapCurve(Internal.Curve.async);

        })();
        window.util = (function() {
            'use strict';

            var StaticArrayBufferProto = new ArrayBuffer().__proto__;

            return {
                toString: function(thing) {
                    if (typeof thing == 'string') {
                        return thing;
                    }
                    return new dcodeIO.ByteBuffer.wrap(thing).toString('binary');
                },
                toArrayBuffer: function(thing) {
                    if (thing === undefined) {
                        return undefined;
                    }
                    if (thing === Object(thing)) {
                        if (thing.__proto__ == StaticArrayBufferProto) {
                            return thing;
                        }
                    }

                    var str;
                    if (typeof thing == "string") {
                        str = thing;
                    } else {
                        throw new Error("Tried to convert a non-string of type " + typeof thing + " to an array buffer");
                    }
                    return new dcodeIO.ByteBuffer.wrap(thing, 'binary').toArrayBuffer();
                },
                isEqual: function(a, b) {
                    // TODO: Special-case arraybuffers, etc
                    if (a === undefined || b === undefined) {
                        return false;
                    }
                    a = util.toString(a);
                    b = util.toString(b);
                    var maxLength = Math.max(a.length, b.length);
                    if (maxLength < 5) {
                        throw new Error("a/b compare too short");
                    }
                    return a.substring(0, Math.min(maxLength, a.length)) == b.substring(0, Math.min(maxLength, b.length));
                },
                hexToArrayBuffer: function(str) {
                    var ret = new ArrayBuffer(str.length / 2);
                    var array = new Uint8Array(ret);
                    for (var i = 0; i < str.length/2; i++)
                        array[i] = parseInt(str.substr(i*2, 2), 16);
                    return ret;
                },
                strEncodeToBase64: function(str){
                    // str to base64
                    var encode = encodeURI(str);
                    var base64 = btoa(encode);
                    return base64;
                },
                base64DecodeToStr: function(base64){
                    // base64 to str
                    var decode = atob(base64);
                    var str = decodeURI(decode);
                    return str;
                },
                cutArraybuffer: function (input_ab,num) {
                    let newArrayBuffer = new ArrayBuffer(num);
                    let edit = new Uint8Array(newArrayBuffer);
                    let inputViewer = new Uint8Array(input_ab);
                    let count = 0;
                    for (const inputViewerCount of inputViewer) {
                        if (count == num) {break;}
                        edit[count] = inputViewerCount;
                        count++;
                    }
                    return newArrayBuffer;
                }
            };
        })();