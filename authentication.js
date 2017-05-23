/* Use UTF-8 to operate this file*/
/*
 * 此模块处理权限相关问题，包括获取token、更改密码、更改权限之类
 * @author hanyuwei70 hanyuwei70@qq.com
 * */
"use strict";
const _=require('lodash');
const express=require('express');
const crypto=require('crypto');
const data=require('./datasource');
const config = require("./config.js");
const debug=require('debug')('authentication');
const async = require('async');
let router = express.Router();
/*
* 用户管理权限系统
* * root (UID=0) 最高权限
* + users.security_edit 对所有用户都具有修改权 包括安全信息
*   |
*   + users.edit 对所有用户都具有修改权 不包括安全信息
*     |
*     + users.view 可以查看所有用户的信息
* + user.<user_id> 对特定的用户具有的权限 (一般不使用)
* 每个用户对自己有 security_edit 权限，无法配置
* 可能后续增加用户组，放在另外一个模块里
* */
/*
* 请求/续期token
* @param {string} username 用户名
* @param {string} password 密码
* */
function login(req,resp){
    let username=req.body.username,
        password=req.body.password,
        token=req.body.token;
    if (req.url==="/login"){ //登录
        debug('logging username:'+username+" password:"+password);
        if (!_.isString(username) || !_.isString(password) || _.isEmpty(username) || _.isEmpty(password)){
            resp.status(401).end();
            return;
        }
        data.User.findByName(username,function (err,user){
            if (err){
                debug('login 500');
                resp.status(500).write(JSON.stringify({error:"服务器内部错误"}));
                console.log(err);
                resp.end();
                return;
            }
            if (user!==undefined && user.checkPass(password)) {
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够 //TODO:重写
                    if (err){
                        debug('login 500');
                        resp.status(500).end();
                        return;
                    }
                    let expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime;
                    user.requireToken(expiretime,function(err,token){
                        if (err) {resp.status(500).end();console.log(err);return;}
                        debug('login 200 token:'+token.toString('hex'));
                        resp.status(200);
                        resp.json({token:token.toString('hex'),expiretime:expiretime,userid:user.data.userid})
                        resp.end();
                    });
                });
            }else{
                debug('login 401');
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
                        data.User.clearToken(token,function (err) {
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
* 表单
*   @param {string} token (已变成req.user)
*   @param {string} token_req 请求注销的token
* */
//TODO:注销token重写，改成可以选择token注销，同时让管理员有权限注销 token
function logout(req,resp) {
    let token_req=req.body.token_req;
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
        data.User.clearToken(token_req,function(err){
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
* 表单:
*   @param {string} token (已转换为req.user)
*   @param {string} [userid] 需要列出的用户ID(默认为req.user)
* */
function listToken() {
    //TODO:实现
    //TODO:实现授权
}
/*
* 修改用户密码
* 表单:
* @param {string} token 用户token (已在前面处理为req.user)
* @param {string} userid 需要修改的用户ID
* @param {string} newpassword 新密码
* */
function changepassword(req,resp){
    debug('processing changepassword');
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
            data.User.clearAllToken(user.data.userid,function (err) {
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
 * 添加用户
 * 表单
 * @param {string} username 用户名
 * @param {string} password 明文密码
 * @param {string} [nickname] 昵称
 * */
function adduser(req,resp){
    debug('adduser processing');
    var newuser=new data.User();
    newuser.data.username=req.body.username;
    var plainpass=req.body.password;
    newuser.data.nickname=req.body.nickname;
    if (_.isEmpty(newuser.data.username) || !_.isString(newuser.data.username)|| newuser.data.username.match(/\s/) ||
        _.isEmpty(plainpass) || !_.isString(plainpass)){
        resp.status(400).write(JSON.stringify({error:"username or password missing"}));
        debug('adduser return 400');
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
        if (err) {
            if (err.errno===19){
                //碰到SQL约束
                if (err.message.indexOf("users.username")!==-1){
                    //用户名重名
                    resp.status(409).write(JSON.stringify({error:"username existed"}));
                    debug('adduser 409');
                    resp.end();
                }else{
                    debug('adduser 500');
                    resp.status(500).end();
                }
            }else{
                debug('adduser 500 err:'+err);
                resp.status(500).end();
            }
        }else {
            debug('adduser 200');
            resp.status(200).end();
        }
    });
}
/*
* 执行验证(authentication)职能
* TODO:重写,使其只执行验证功能
* @param {string} [token] 用户令牌
* 如果存在用户令牌，将会转换为req.user
* */
/*
* 检查是否为静态请求
* */
function isStatic(path) {
    let suffix=[".html",".css",".js",".jpg"],
        spec_url=["/"],
        suffix_res,
        spec_res;
    suffix_res=suffix.find(function (e) {
        return path.endsWith(e)
    });
    spec_res=spec_url.find(function (e) {
        return path===e;
    });
    return suffix_res!==undefined || spec_res!==undefined;
}
/*
* 验证模块
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
        });
    }
}
/*
* 计算权限节点树
* resource目前只有user.<id>
* */
function calcPermission(role,resource,action,callback) {
    if (role==="user.0") return callback(null,true);
    let resultcb=function (err,results) {
        let ans=results.find(function (e) {
            return e.value==1;
        });
        return callback(ans!==undefined);
    };
    if (role===resource) return callback(null,true);
    if (action==="security_edit"){
        async.parallel(async.reflectAll([
            function (cb) {data.Authorize.getPermission(role,"users",action,cb);},
            function (cb) {data.Authorize.getPermission(role,resource,action,cb);}
        ]),resultcb);
    }else if (action==="edit"){
        async.parallel(async.reflectAll([
            function (cb) {data.Authorize.getPermission(role,"users",action,cb);},
            function (cb) {data.Authorize.getPermission(role,resource,action,cb);},
            function (cb) {data.Authorize.getPermission(role,"users","security_edit",cb);},
            function (cb) {data.Authorize.getPermission(role,resource,"security_edit",cb);}
        ]),resultcb);
    }else if (action==="view"){
        async.parallel(async.reflectAll([
            function (cb) {data.Authorize.getPermission(role,"users",action,cb);},
            function (cb) {data.Authorize.getPermission(role,resource,action,cb);},
            function (cb) {data.Authorize.getPermission(role,"users","security_edit",cb);},
            function (cb) {data.Authorize.getPermission(role,resource,"security_edit",cb);},
            function (cb) {data.Authorize.getPermission(role,"users","edit",cb);},
            function (cb) {data.Authorize.getPermission(role,resource,"edit",cb);}
        ]),resultcb);
    }
}
/*
* 执行authentication模块授权任务，即用户系统权限
* */
function authorization(req,resp,next){
    async.series([
        function (callback) {
            debug('authorize: '+req.path);
            let pass=["/login","/user/getinfo"]; //无条件通过的请求地址
            if (pass.indexOf(req.path)!=-1){ //无条件通过
                callback(null);
            }else if (isStatic(req.path)){ //静态文件
                callback(null);
            } else if (_.isEmpty(req.user)){ //授权信息检查
                callback(null,{status:401});
            }else if (req.user.getID()===0){ //是否为root？
                callback(null);
            }else if (req.path==="/listtoken" || req.path==="/changepassword"){
                calcPermission("user."+req.user.getID(),"user."+req.body.userid,"security_edit",function (err,result) {
                    if (err) callback(err);
                    else callback(null,result?undefined:{status:403});
                });
            }else if (req.path==="/register"){
                calcPermission("user"+req.user.getID(),"users","security_edit",function (err,result) {
                    if (err) callback(err);
                    else callback(null,result?undefined:{status:403});
                });
            }else{ //不属本模块管辖的授权，通行
                callback(null);
            }
        }
    ],function (err,result) {
        if (result!==undefined){
            result=result[0];
        }
        if (err){
            resp.status(500).end();
            debug('authorize 500');
            return;
        }
        if (result===undefined || result.status===undefined){
            debug('authorize next');
            if (process.env.BRUTEFORCE==="yes"){
                req.brute.reset();
            }
            next();
        }else{
            debug('authorize '+result.status);
            resp.status(result.status);
            if (result.msg!==undefined) //TODO:仔细检查result类型
                resp.write(JSON.stringify({error:result.msg}));
            resp.end();
        }
    });
}
router.use(authentication); //做token验证
router.use(authorization);
router.post('/login',login);
router.post('/renew',login);
router.post('/logout',logout);
router.post('/changepassword',changepassword);
router.post('/register',adduser);
router.post('/listtoken',listToken);
module.exports=router;
//TODO:新增删除用户