/* Use UTF-8 to operate this file*/
/*
 * 此模块处理权限相关问题，包括获取token、更改密码、更改权限之类
 * @author hanyuwei70 hanyuwei70@qq.com
 * */
var _=require('lodash');
var express=require('express');
var crypto=require('crypto');
var data=require('./datasource');
var config = require("./config.js");
var debug=require('debug')('authentication');
var async=require('async');
var redis=require('redis'),
    rdsclient=redis.createClient();
rdsclient.on("error",function (err) {
    console.log("REDIS CLIENT ERROR:"+err);
});
var router=express.Router();
/*
* 用户管理权限系统
* * root (UID=0) 最高权限
* * user.modify 可以修改所有用户数据
* - * user.add 添加用户
* */
//TODO:完成所有请求的权限控制
/*
* 请求/续期token
* @param {string} username 用户名
* @param {string} password 密码
* */
function login(req,resp){
    var username=req.body.username,
        password=req.body.password,
        token=req.body.token;
    if (req.url==="/login"){ //登录
        debug('username:'+username+" password:"+password);
        if (!_.isString(username) || !_.isString(password) || _.isEmpty(username) || _.isEmpty(password)){
            resp.status(401).end();
            return;
        }
        data.User.findByName(username,function (err,user){
            if (err){
                resp.status(500).write(JSON.stringify({error:"服务器内部错误"}));
                console.log(err);
                resp.end();
                return;
            }
            if (user!==undefined && user.checkPass(password)) {
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够 //TODO:重写
                    if (err){
                        resp.status(500).end();
                        return;
                    }
                    var expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime;
                    user.requireToken(expiretime,function(err,token){
                        if (err) {resp.status(500).end();console.log(err);return;}
                        resp.status(200).write(JSON.stringify({token:token.toString('hex'),expiretime:expiretime,userid:user.data.userid}));
                        resp.end();
                    });
                });
            }else{
                resp.status(401);
                resp.write(JSON.stringify({error:"username and password mismatch"}));
                resp.end();
            }
        });
    }
    else if (req.url==="/renew"){ //续期token
        debug('renewing token:'+token);
        if (!_.isString(token)||_.isEmpty(token)){
            resp.status(401).end();
            return;
        }
        data.User.findByToken(token,function (err,user){
            if (err){
                resp.status(500).write(JSON.stringify({error:"服务器内部错误"}));
                console.log(err);
                resp.end();
                return;
            }
            if (user!==undefined){
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够
                    if (err){
                        resp.status(500).end();
                        return;
                    }
                    var expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime;
                    user.requireToken(expiretime,function(err,newToken){
                        if (err){
                            resp.status(500).end();
                            return;
                        }
                        user.clearToken(token,function (err) {
                            if (err){
                                resp.status(500).end();
                            }else{
                                debug('old token revoked');
                                resp.status(200).write(JSON.stringify({token:newToken.toString('hex'),expiretime:expiretime}));
                                resp.end();
                            }
                        });
                    });
                });
            }else{
                resp.status(401).write(JSON.stringify({error:"Token is invalid"}));
                resp.end();
            }
        });
    }
    else{ //操作不支持
        resp.status(501);
        resp.write(JSON.stringify({error:"operation not implemented."}));
        resp.end();
    }
}
/*
* 注销token
* 权限
*   - user.modify
*   普通用户可以注销自己的任意token
* 表单
*   @param {string} token (已变成req.user)
*   @param {string} token_req 请求注销的token
* */
//TODO:注销token重写，改成可以选择token注销，同时让管理员有权限注销 token
function logout(req,resp) {
    var token_req=req.body.token_req;
    debug('logout processing');
    data.User.findByToken(token_req,function(err,user){
        if (err){
            resp.status(500);
            console.log(err);
            resp.write(JSON.stringify({error:"Internal Server Error"}));
            resp.end();
            return;
        }
        if (user===undefined){
            debug('the user of token not found');
            resp.status(401).write(JSON.stringify({error:"the user of token not found"}));
            resp.end();
            return;
        }
        debug('token found,revoking');
        user.clearToken(token_req,function(err){
            if (err) {
                resp.status(500);
                resp.write(JSON.stringify({error:"Internal Server Error"}));
                resp.end();
                return;
            }
            debug('token revoked');
            resp.status(200).write(JSON.stringify({msg:"Token revoked"}));
            resp.end();
        });
    });
}
/*
* 列出某个用户所有token
* 权限
*   - user.modify
* 用户默认只可以列出自己的所有token
* 授权在自己这里完成
* 表单:
*   @param {string} token (已转换为req.user)
*   @param {string} [uid] 需要列出的用户ID(默认为req.user)
* */
function listToken() {
    //TODO:实现
    //TODO:实现授权
}
    

/*
* 修改用户密码
* 权限:
*   - user.changepassword / user.changepassword.<user_id>
* 默认用户可以更改自己的密码，无需添加节点
* 表单:
* @param {string} token 用户token (已在前面处理为req.user)
* @param {string} userid 需要修改的用户ID
* @param {string} newpassword 新密码
* */
function changepassword(req,resp){
    var uid_req=req.body.userid,
        newpass=req.body.newpassword;
    if (!_.isInteger(uid_req) || !_.isString(newpass) || _.isEmpty(newpass)){
        resp.status(400).write(JSON.stringify({error:"missing arguments"}));
        resp.end();
        return;
    }
    data.User.findById(uid_req,function(err,user){
        if (err){
            resp.status(500);
            resp.write(JSON.stringify({error:"Internal Server Error"}));
            resp.end();
            return;
        }
        if (user===undefined){
            resp.status(404).write(JSON.stringify({error:"requested user not found"}));
            resp.end();
            return;
        }
        user.setPass(newpass,function(err){
            if (err){
                resp.status(500).end();
                return;
            }
            user.clearallToken(user.data.userid,function (err) {
                if (err){
                    resp.status(500);
                    resp.write(JSON.stringify({error:"Internal Server Error"}));
                    resp.end();
                    return;
                }
                user.save(function (err) {
                    if (err){
                        resp.status(500).end();
                        return;
                    }
                    resp.status(200).end();
                });
            });
        });
    });
}
/*
* 执行验证(authentication)职能
* TODO:重写,使其只执行验证功能
* @param {string} [token] 用户令牌
* 如果存在用户令牌，将会转换为req.user
* */
function authentication(req, resp, next){
    var token=req.body.token;
    //debug("authenticating...");
    if (req.originalUrl==="/login") next(); //登录请求不检查
    else if (req.originalUrl==="/") next();
    else if (req.originalUrl.endsWith(".html")) next();
    else if (req.originalUrl.endsWith(".js")) next();
    else if (req.originalUrl.endsWith(".css")) next();
    /*data.User.findByName(username,function (err,user){
        if (err) throw err;
        if (user===undefined || !user.checkToken(token)){ // token的有效期计时按照执行到datasource module的时间计算
            resp.type("json");
            resp.writeHead(403).json({msg:"Token is invalid"});
            resp.end();
        }
    });*/
    else{
        data.User.findByToken(token,function (err,user){
            //WARN:不要在if里面写next(),权限通过之后让控制流掉到最后一个next()去
            if (err){
                resp.status(500);
                resp.write(JSON.stringify({error:"Internal Server Error"}));
                resp.end();
                return;
            }
            req.user=user;
            next();
            //TODO:实现检查用户的权限和各个操作所需要的权限比对
        });
    }
}
/*
* 执行authentication模块授权任务，即用户系统权限
* */
function authorization(req,resp,next){
    async.series([
        function (callback) {
            debug('authorize: '+req.path);
            switch (req.path){
                case "/login":
                case "/renew":
                case '/listtoken': // listtoken在自己那里完成授权
                case "/logout":
                    return callback(null);
                    break;
                case "/changepassword":
                    if (req.user===undefined || req.user===null)
                        return callback(null,{status:401});
                    if (req.user.getID()===req.body.userid || req.user.getID()===0)
                        return callback(null);
                    //TODO:检查"user.changepassword"和"user.changepassword.<user_id>节点"
                    return callback(null,{status:403,msg:"in changepassword"});
                    break;
                case "/adduser":
                    if (req.user===undefined || req.user===null)
                        return callback(null,{status:401});
                    if (req.user.getID()===0)
                        return callback(null);
                    //TODO:检查 "user.add"节点
                    return callback(null,{status:403,msg:"in adduser"});
                    break;
                default:
                    callback(null);
            }
        }
    ],function (err,result) {
        if (result!==undefined){
            result=result[0];
        }
        debug('authorize result: err:'+err+' result:'+result);
        if (err){
            resp.status(500).end();
            return;
        }
        if (result===undefined || result.status===undefined){
            next();
        }else{
            resp.status(result.status);
            if (result.msg!==undefined) //TODO:仔细检查result类型
                resp.write(JSON.stringify({error:result.msg}));
            resp.end();
        }
    });
}
/*
* 添加用户
* 权限节点
*   -user.add
* 表单
* @param {string} username 用户名
* @param {string} password 明文密码
* @param {string} [nickname] 昵称
* */
function adduser(req,resp){
    var newuser=new data.User();
    newuser.data.username=req.body.username;
    var plainpass=req.body.password;
    newuser.data.nickname=req.body.nickname;
    if (_.isEmpty(newuser.data.username) || !_.isString(newuser.data.username)|| newuser.data.username.match(/\s/) ||
        _.isEmpty(plainpass) || !_.isString(plainpass)){
        resp.status(400).write(JSON.stringify({error:"username or password missing"}));
        resp.end();
        return;
    }
    async.series([
        function (callback) {
            debug('adduser setting password');
            newuser.setPass(plainpass,function (err) {
                if (err)
                    return callback(err);
                else
                    return callback(null);
            });
        },
        function (callback) {
            debug('adduser saving user');
            newuser.save(function (err) {
                if (err)
                    return callback(err);
                else
                    return callback(null);
            });
        }
    ],function (err,result) {
        debug("adduser err:"+err);
        if (err) {
            if (err.errno===19){
                //碰到SQL约束
                if (err.message.indexOf("users.username")!==-1){
                    //用户名重名
                    resp.status(409).write(JSON.stringify({error:"username existed"}));
                    resp.end();
                }else{
                    resp.status(500).end();
                }
            }else{
                resp.status(500).end();
            }
        }else {
            resp.status(200).end();
        }
    });
}
/*
 * @callback privilegeNodeCallback
 * @param {Object} err - 错误
 * @param {int|boolean} result - 操作结果
 * */
/*
* 查询节点
* @param {int} id 用户ID
* @param {string} priv 权限节点
* @param {privilegeNodeCallback} callback 回调
* */
function querynode(id,priv,callback){
    rdsclient.sismember(priv,id,function (err,reply) {
        if (err) {callback(err);return;}
        callback(null,reply===1);
    });
}
/*
* 添加权限节点
* @param {int} id 用户ID
* @param {string} priv 权限节点
* @param {privilegeNodeCallback} callback 回调
* */
function addnode(id,priv,callback){
    data.User.findById(id,function (err,user) {
        if (err){callback(err);return;}
        if (user===undefined) {callback(new Error("user not found"));return;}
        rdsclient.sadd(priv,id,function (err,reply) {
            if (err) callback(err);
            //TODO:加上错误处理
            callback(null,true);
        });
    });
}
/*
* 删除权限节点
* @param {int} id 用户ID
* @param {string} 权限节点
* @param {privilegeNodeCallback} callback 回调
* */
function delnode(id,priv,callback){
    data.User.findById(id,function(err,user){
        if (err) {callback(err);return;}
        if (user===undefined) {callback(new Error("user not found"));return;}
        rdsclient.del(priv);
        callback(null,1);
    });
}
router.use(authentication); //做token验证
router.use(authorization);
router.post('/login',login);
router.post('/renew',login);
router.post('/logout',logout);
router.post('/changepassword',changepassword);
router.post('/adduser',adduser);
router.post('/listtoken',listToken);
module.exports=router;
exports.querynode=querynode;
exports.addnode=addnode;
exports.delnode=delnode;
