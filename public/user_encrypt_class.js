class local_db {
    // 数据库操作
	constructor(name,dblist) {
		var that = this;
        // 本地数据库配置
        localforage.config({
            driver      : [
                localforage.INDEXEDDB,
                localforage.LOCALSTORAGE,
                localforage.WEBSQL
            ],
            name        : name,
            version     : 1.0,
            size        : 4980736,
            storeName   : 'Gmsg',
            description : ''
        }).then(()=>{
            that.name = name
            that.dblist = {};
        }).then(()=>{
            that.initDB(dblist).then((dblist)=>{
                console.log(dblist);
            })
        });
	}

	initDB(list){
        // 对库中的表进行实例化
		var that = this;
		return new Promise((resolve,reject)=>{
			async function localfunc(){
				try {
					await localforage.ready()
					for (const iterator of list) {
						// 实例化数据库
						if (typeof that.dblist === "undefined") {
							that.dblist = {};
						}
						that.dblist[iterator] = localforage.createInstance({
							name: that.name,
							storeName: iterator,
                            description : '...'
						});
					}
					return resolve(that.dblist);
				} catch (error) {
					return reject(error)
				}
			}
			return localfunc();
		});
	}

	put(dbname,key,val){
		return this.dblist[dbname].setItem(key,val);
	}

	get(dbname,key){
		var that = this;
		return new Promise((resolve,reject)=>{
			async function localfunc(key){
				try {
					var result = await that.dblist[dbname].getItem(key)
				} catch (error) {
					reject(error)
				}finally{
					console.log(result)
					resolve(result);
				}
			}
			localfunc(key);
		});
	}
	
	del(dbname,key){
		try {
			this.dblist[dbname].removeItem(key)
		} catch (error) {
			console.log(error)
		}
	}
	
	
	length(dbname){
		var that = this;
		return new Promise((resolve,reject)=>{
			async function localfunc(){
				try {
					var result = await that.dblist[dbname].length();
				} catch (error) {
					console.log(error)
				}finally{
					resolve(result)
				}
			}
			localfunc()
		});
	}

	async clean(dbname){
		try {
			this.dblist[dbname].clear();
		} catch (error) {
			console.log(error)
		}
	}
}

class Queue{
    // 队列模块

    constructor(items_count){
        this.items_count = items_count || 2000; // 队列尺寸
        this.items = []; // 队列实体
    }

    enqueue_to_head(input) {
        // 头部入队
        this.items.unshift(input)
        if (this.items_count < this.items.length) {
            // 若数据入队，则将旧数据挤出
            return this.dequeue_from_tail();
        }else{
            return false;
        }
    }

    dequeue_from_head() {
        // 头部出队
        var result = this.items.shift();
        return typeof result != 'undefined' ? result : false;
    }

    enqueue_to_tail(input) {
        // 尾部入队
        this.items.push(input)
        if (this.items_count < this.items.length) {
            // 若数据入队，则将旧数据挤出
            return this.dequeue_from_head();
        }else{
            return false;
        }
    }

    dequeue_from_tail() {
        // 尾部出队
        var result = this.items.pop();
        return typeof result != 'undefined' ? result : false;
    }

    isEmpty() {
        // 队列是否空
        return this.items.length == 0;
    }

    clearQueue(){
        //清空队列
        this.items = [];
    }

    showQueue(){
        console.log("show Queue:")
        for (let index = 0; index < this.items.length; index++) {
            console.log(index+":",this.items[index]);
        }
    }
}

class user_encrypt_class{
    constructor(name,mobile,email){
        this.name = name;
        this.mobile = mobile;
        this.email = email;
        this.registrationId;
        this.Identity_Key_Pair;
        this.Signed_Pre_Key;
        this.preKeys = [];
        this.Einitiator_pub;
        this.Einitiator;
        this.rootkey;
        this.ChainKeys;
        this.IV;
        this.Iteration = 0;
        this.encrypt_DH_array = [];
        this.decrypt_DH_array = [];
        this.master_secret;
        this.seed = util.toArrayBuffer("seed");

        this.encrypt_keys = {
            master_secret : null,
            rootkey : null,
            ChainKeys : null,
            IV : null,
            Iteration : 0
        }

        this.decrypt_keys = {
            master_secret : null,
            rootkey : null,
            ChainKeys : null,
            IV : null,
            Iteration : 0
        }
        this.friend_publickey;

        this.DH_friend_array = [];
        this.friend_IterationCache = new Queue();
    }

    export_environment_data(){
        // 导出加密数据环境用于保存在数据库中
        return {
            name : this.name,
            mobile : this.mobile,
            email : this.email,
            registrationId : this.registrationId,
            Identity_Key_Pair : this.Identity_Key_Pair,
            Signed_Pre_Key : this.Signed_Pre_Key,
            preKeys : this.preKeys,
            Einitiator_pub : this.Einitiator_pub,
            Einitiator : this.Einitiator,
            rootkey : this.rootkey,
            ChainKeys : this.ChainKeys,
            IV : this.IV,
            Iteration : this.Iteration,
            encrypt_DH_array : this.encrypt_DH_array,
            decrypt_DH_array : this.decrypt_DH_array,
            master_secret : this.master_secret,
            seed : this.seed,
            encrypt_keys : this.encrypt_keys,
            decrypt_keys : this.decrypt_keys,
            friend_publickey : this.friend_publickey,
            DH_friend_array : this.DH_friend_array,
            friend_IterationCache : this.friend_IterationCache.items
        }
    }

    import_environment_data(data){
        // 将加密数据环境导入
        this.name = data.name;
        this.mobile = data.mobile;
        this.email = data.email;
        this.registrationId = data.registrationId;
        this.Identity_Key_Pair = data.Identity_Key_Pair;
        this.Signed_Pre_Key = data.Signed_Pre_Key;
        this.preKeys = data.preKeys;
        this.Einitiator_pub = data.Einitiator_pub;
        this.Einitiator = data.Einitiator;
        this.rootkey = data.rootkey;
        this.ChainKeys = data.ChainKeys;
        this.IV = data.IV;
        this.Iteration = data.Iteration;
        this.encrypt_DH_array = data.encrypt_DH_array;
        this.decrypt_DH_array = data.decrypt_DH_array;
        this.master_secret = data.master_secret;
        this.seed = data.seed;

        this.encrypt_keys = data.encrypt_keys;

        this.decrypt_keys = data.decrypt_keys;
        this.friend_publickey = data.friend_publickey;

        this.DH_friend_array = data.DH_friend_array;

        this.friend_IterationCache = new Queue();
        this.friend_IterationCache.items = data.friend_IterationCache;
    }

    get_friend_publickey(input){
        var friend_publickey = JSON.parse(util.base64DecodeToStr(input))
        // 获取好友的公钥
        var that = this;
        that.friend_publickey = {
            name:friend_publickey.name,
            registrationId:friend_publickey.registrationId,
            Iteration : 0,
            Einitiator_pub : util.toArrayBuffer(util.base64DecodeToStr(friend_publickey.Einitiator_pub)),
            Irecipient : util.toArrayBuffer(util.base64DecodeToStr(friend_publickey.Irecipient)),
            Srecipient : util.toArrayBuffer(util.base64DecodeToStr(friend_publickey.Srecipient)),
            Orecipient : [util.toArrayBuffer(util.base64DecodeToStr(friend_publickey.Orecipient[0]))]
        };
        return Promise.resolve(that.friend_publickey)
        .then(that.Create_DH_for_encrypt(that.friend_publickey))
        .then(that.Create_DH_for_decrypt(that.friend_publickey))
        .then(()=>{
            return that.friend_publickey;
        })
    }

    generateUserKeyPair() {
        //生成用户密钥组
        var that = this;
        var privKey;
        // console.log(that.name,"正在创建密钥对")
        // console.log("生成身份秘钥对")
        // console.log("首先,生成私钥")
        privKey = Internal.crypto.getRandomBytes(32);
        // console.log("用生成的私钥生成公钥")
        return Internal.Curve.async.createKeyPair(privKey).then((Identity_Key_Pair)=>{
            // console.log("身份秘钥对生成完成")
            // console.log(Identity_Key_Pair)
            that.Identity_Key_Pair = Identity_Key_Pair;
            return Identity_Key_Pair;
        }).then((Identity_Key_Pair)=>{
            privKey = Internal.crypto.getRandomBytes(32);
            Internal.Curve.async.createKeyPair(privKey).then((KeyPair)=>{
                // console.log(KeyPair)
                return Internal.crypto.Ed25519Sign(Identity_Key_Pair.privKey, KeyPair.pubKey).then(function(sig) {
                    that.Signed_Pre_Key = {
                        keyPair    : KeyPair,
                        signature  : sig
                    };
                    // console.log("生成已签名的预共享密钥对")
                    // console.log({
                    //     keyPair    : KeyPair,
                    //     signature  : sig
                    // })
                });
            })
        }).then(()=>{
            for (var index = 0; index < 1; index++) {
                privKey = Internal.crypto.getRandomBytes(32);
                Internal.Curve.async.createKeyPair(privKey).then((keyPair)=>{
                    // console.log("生成一次性的预密钥")
                    // console.log(keyPair)
                    that.preKeys.push(keyPair);
                });
            }
        }).then(()=>{
            // console.log("生成用户注册ID")
            var registrationId = new Uint16Array(Internal.crypto.getRandomBytes(2))[0];
            that.registrationId = registrationId & 0x3fff;
            console.log("用户注册ID生成完成",that.registrationId)
        }).then(()=>{
            // 开始生成临时Curve25519密钥对
            return that.Curve25519_createKeyPair().then((k)=>{
                // console.log(k)
                that.Einitiator_pub = k.pubKey;
                that.Einitiator = k.privKey
                
                return that.publicKeyPair()
            });
        })
    }

    publicKeyPair(){
        // 对外输出公钥组
        var pubs = [];
        for (let index = 0; index < this.preKeys.length; index++) {
            pubs.push(this.preKeys[index].pubKey);
        }
        return util.strEncodeToBase64(JSON.stringify({
            name:this.name,
            registrationId:this.registrationId,
            Iteration : 0,
            Einitiator_pub : util.strEncodeToBase64(util.toString(this.Einitiator_pub)),
            Irecipient : util.strEncodeToBase64(util.toString(this.Identity_Key_Pair.pubKey)),
            Srecipient : util.strEncodeToBase64(util.toString(this.Signed_Pre_Key.keyPair.pubKey)),
            Orecipient : [util.strEncodeToBase64(util.toString(pubs[0]))]
        }))
    }

    Curve25519_createKeyPair() {
        // console.log("生成临时Curve25519密钥对")
        return Internal.Curve.async.createKeyPair(Internal.crypto.getRandomBytes(32));
    }

    create_IV(input){

        let IV = new ArrayBuffer(16);
        let edit = new Uint8Array(IV);
        let Uint8 = new Uint8Array([].slice.call(input));
        let count = 0;
        for (const Uint8count of Uint8) {
            if (count == 16) {break;}
            edit[count] = Uint8count;
            count++;
        }
        return IV;
    }

    init_Rotate_ratchet(DH_array,cb){
        var that = this;
        // 生成主密钥
        let master_secret = util.toArrayBuffer(util.toString(DH_array[0])+util.toString(DH_array[1])+util.toString(DH_array[2])+util.toString(DH_array[3]));
        // console.log(that.master_secret)
        // 初始化棘轮参数
        that.Rotate_ratchet(
            1,
            0,
            master_secret,
            master_secret,
            that.create_IV(master_secret),
            that.seed,
            that.seed,
            cb
        )
    }

    Create_DH_for_encrypt(friend_publickey){
        // console.log("创建加密的DH棘轮")
        var that = this;
        return Promise.all([
            Internal.crypto.ECDHE(friend_publickey.Srecipient, this.Identity_Key_Pair.privKey),
            Internal.crypto.ECDHE(friend_publickey.Irecipient, this.Einitiator),
            Internal.crypto.ECDHE(friend_publickey.Srecipient, this.Einitiator),
            Internal.crypto.ECDHE(friend_publickey.Orecipient[0], this.Einitiator)
        ]).then((values) => {
            // console.log("Promise.all:");
            // that.encrypt_DH_array = values;
            that.init_Rotate_ratchet(values,(rootkey,ChainKeys,IV,IterationCache)=>{
                // 获取棘轮初始化的结果
                that.encrypt_keys.rootkey = rootkey;
                that.encrypt_keys.ChainKeys = ChainKeys;
                that.encrypt_keys.IV = IV;
            })

        });
    }

    Create_DH_for_decrypt(friend_publickey){
        // console.log("创建加密的DH棘轮")
        var that = this;
        Promise.all([
            Internal.crypto.ECDHE(friend_publickey.Irecipient, this.Signed_Pre_Key.keyPair.privKey),
            Internal.crypto.ECDHE(friend_publickey.Einitiator_pub, this.Identity_Key_Pair.privKey),
            Internal.crypto.ECDHE(friend_publickey.Einitiator_pub, this.Signed_Pre_Key.keyPair.privKey),
            Internal.crypto.ECDHE(friend_publickey.Einitiator_pub, this.preKeys[0].privKey)
        ]).then((values) => {
            // console.log("Promise.all:");
            // that.decrypt_DH_array = values;
            that.init_Rotate_ratchet(values,(rootkey,ChainKeys,IV,IterationCache)=>{
                // 获取棘轮初始化的结果
                that.decrypt_keys.rootkey = rootkey;
                that.decrypt_keys.ChainKeys = ChainKeys;
                that.decrypt_keys.IV = IV;
                that.friend_IterationCache.enqueue_to_head({
                    Iteration : 0,
                    ChainKeys : ChainKeys,
                    IV : IV
                })
            })
        });
    }

    encrypt_msg(text,cb){
        // 对消息进行加密
        var that = this;
        // 先将消息base64进行编码，再转二进制，通过 AES256 消息密钥加密（CbC 模式）
        let encodetext = util.toArrayBuffer(util.strEncodeToBase64(text));
        // console.log(encodetext)
        // 此处放置棘轮转动
        return Internal.crypto.encrypt(that.encrypt_keys.ChainKeys, encodetext, that.encrypt_keys.IV).then((result)=>{
            // 该处要对消息进行签名
            return Internal.crypto.Ed25519Sign(that.Einitiator, result).then(function(sigCalc) {
                // 签名完成
                
                if (typeof cb === "function") {
                    cb({
                        registrationId : that.registrationId,
                        name : that.name,
                        mobile : that.mobile,
                        email : that.email,
                        sigCalc : util.strEncodeToBase64(util.toString(sigCalc)),
                        result : util.strEncodeToBase64(util.toString(result)),
                        Iteration : that.encrypt_keys.Iteration
                    })
                }
                return {
                    registrationId : that.registrationId,
                    name : that.name,
                    mobile : that.mobile,
                    email : that.email,
                    sigCalc : util.strEncodeToBase64(util.toString(sigCalc)),
                    result : util.strEncodeToBase64(util.toString(result)),
                    Iteration : that.encrypt_keys.Iteration
                }
            }).then(function (r) {
                // 消息加密并且签名后，转动棘轮
                that.Rotate_ratchet(
                    that.encrypt_keys.Iteration+1,
                    that.encrypt_keys.Iteration,
                    that.encrypt_keys.rootkey,
                    that.encrypt_keys.ChainKeys,
                    that.encrypt_keys.IV,
                    util.toArrayBuffer(that.name),
                    that.Einitiator_pub,
                    (rootkey,ChainKeys,IV)=>{
                        // 将更新的 rootkey,ChainKeys,IV
                        that.encrypt_keys.rootkey = rootkey;
                        that.encrypt_keys.ChainKeys = ChainKeys;
                        that.encrypt_keys.IV = IV;
                        that.encrypt_keys.Iteration++;
                    }
                )
                return util.strEncodeToBase64(JSON.stringify(r))
            })
        })

    }

    decrypt_msg(input,cb){
        var that = this;
        
        var msg = JSON.parse(util.base64DecodeToStr(input));
        msg.sigCalc = util.toArrayBuffer(util.base64DecodeToStr(msg.sigCalc))
        msg.result = util.toArrayBuffer(util.base64DecodeToStr(msg.result))
        // 此处对msg先进行签名验证
        Internal.crypto.Ed25519Verify(that.friend_publickey.Einitiator_pub, msg.result, msg.sigCalc).then(function() {
            console.log("签名验证成功");

            // 检查棘轮距离
            that.check_Iteration(
                that.decrypt_keys.Iteration,
                msg.Iteration,
                (ChainKey,IV)=>{
                    Internal.crypto.decrypt(ChainKey, msg.result, IV).then(function(result){
                        cb(true,util.base64DecodeToStr(util.toString(result)))
                    })
                },
                ()=>{
                    if (typeof cb === "function") {
                        cb(false,"erro Iteration")
                    }
                }
            )
        }).catch(function(e) {
            if (e.message === 'Invalid signature') {
                console.log("签名验证失败，非本人发送，抛弃数据包");
            } else { throw e; }
        })
    }

    check_Iteration(currentIteration,newIteration,cb,catchcb){
        // 校验消息的序列
        var that = this;
        
        if (newIteration > currentIteration) {
            // 如果当前用户的棘轮坐标比最新棘轮坐标要旧，那么按照距离进行转动。
            that.Rotate_ratchet(
                newIteration,
                that.decrypt_keys.Iteration,
                that.decrypt_keys.rootkey,
                that.decrypt_keys.ChainKeys,
                that.decrypt_keys.IV,
                util.toArrayBuffer(that.friend_publickey.name),
                that.friend_publickey.Einitiator_pub,
                (rootkey,ChainKeys,IV,IterationCache)=>{
                    /**
                    * 将更新的 rootkey,ChainKeys,IV,Iteration,IterationCache
                    * IterationCache 为棘轮的缓存
                    */
                    that.decrypt_keys.rootkey = rootkey;
                    that.decrypt_keys.ChainKeys = ChainKeys;
                    that.decrypt_keys.IV = IV;
                    that.decrypt_keys.Iteration = IterationCache[IterationCache.length-1].Iteration;

                    for (let IterationCacheCount = 0; IterationCacheCount < IterationCache.length; IterationCacheCount++) {
                        that.friend_IterationCache.enqueue_to_head(IterationCache[IterationCacheCount])
                    }
                    // Iteration 如果是新的，那么就开始转动棘轮
                    
                    // 此处可以运行本地存储代码，将好友的棘轮状态存入。
                    if (typeof cb === "function") {
                        cb(ChainKeys,IV)
                    }
                }
            )

        } else if (newIteration == currentIteration) {
            // 没有任何变化
            if (typeof cb === "function") {
                cb(that.decrypt_keys.ChainKeys,that.decrypt_keys.IV)
            }
        } else if ((newIteration < currentIteration)&&(2000>(currentIteration - newIteration))) {
            // Iteration 如果是旧的，那么就开始在缓存里寻找旧 Iteration
            if (typeof cb === "function") {
                cb(
                    that.friend_IterationCache.items[currentIteration-newIteration].ChainKeys,
                    that.friend_IterationCache.items[currentIteration-newIteration].IV
                )
            }
        } else{
            // 当以上条件不符合时则抛出错误！
            if (typeof catchcb === "function") {
                catchcb();
            }
        }
    }

    Rotate_ratchet(NewIteration,OldIteration,rootkey,ChainKeys,IV,salt,seed,cb) {
        var HKDFcount = NewIteration-OldIteration;
        // Iteration 的缓存队列
        var IterationCache = [];

        // 转动棘轮
        function runHKDF(HKDFcount,rootkey){
            // console.log(rootkey)
            Internal.crypto.HKDF(
                rootkey,
                salt,
                seed
            ).then(function(OKM){

                // 将转轮的中间值存入 Iteration 缓存
                let IV = new ArrayBuffer(16);
                let edit = new Uint8Array(IV);
                let Uint8 = new Uint8Array(OKM[2]);
                let count = 0;
                for (const Uint8count of Uint8) {
                    if (count == 16) {break;}
                    edit[count] = Uint8count;
                    count++;
                }
                IterationCache.push({
                    Iteration : NewIteration - HKDFcount,
                    ChainKeys : OKM[1],
                    IV : IV
                })

                return OKM;
            }).then(function(OKM){
                // 判断转动的距离是否已经达标，如果达标则直接调用回调函数，将数据传出用于加密解密。
                if(HKDFcount == 0){

                    let rootkey = OKM[0];
                    let ChainKeys = OKM[1];
                    let IV = new ArrayBuffer(16);
                    let edit = new Uint8Array(IV);
                    let Uint8 = new Uint8Array(OKM[2]);
                    let count = 0;
                    for (const Uint8count of Uint8) {
                        if (count == 16) {break;}
                        edit[count] = Uint8count;
                        count++;
                    }
                    if(typeof cb === "function"){
                        cb(rootkey,ChainKeys,IV,IterationCache)
                    }

                }else{
                    runHKDF(HKDFcount-1,OKM[0])
                }
            })
        }

        if(HKDFcount > 0){
            runHKDF(HKDFcount-1,rootkey)
        }else if(typeof cb === "function"){
            cb(rootkey,ChainKeys,IV,IterationCache)
        }

    }
}