/* Use UTF-8 to operate this file*/
/*
 * 此模块处理权限相关问题，包括获取token、更改密码、更改权限之类
 * @author hanyuwei70 hanyuwei70@qq.com
 * */
var express=require('express');
var crypto=require('crypto');
var data=require('./datasource');
var config = require("./config.js");
var debug=require('debug');
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
/*
* 请求token
* @param {string} username 用户名
* @param {string} password 密码
* */
function login(req,resp){ //负责给新的token，
    console.log("processing login request:"+req.baseUrl);
    var username=req.body.username,
        password=req.body.password,
        token=req.body.token;
    if (req.url==="/login"){ //登录
        console.log("login():processing /login");
        data.User.findByName(username,function (err,user){
            if (err){
                resp.status(500).write(JSON.stringify({error:"服务器内部错误"}));
                console.log(err);
                resp.end();
                return;
            }
            if (user!==undefined && user.checkPass(password)) {
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够 //TODO:重写
                    if (err) throw (err);
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
        data.User.findByName(username,function (err,user){
            if (err){
                resp.status(500).write(JSON.stringify({error:"服务器内部错误"}));
                console.log(err);
                resp.end();
                return;
            }
            if (user!==undefined){
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够
                    if (err) throw (err);
                    var expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime;
                    user.setToken(buf,expiretime,function(err){
                        if (err) throw (err);
                        resp.status(200).write(JSON.stringify({token:token,expiretime:expiretime}));
                        resp.end();
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
* @param
* */
function logout(req,resp) { //实质为注销token
    var token_req=req.body.token_req;
    data.User.findByToken(token_req,function(err,user){
        if (err){
            resp.status(500);
            resp.write(JSON.stringify({error:"Internal Server Error"}));
            resp.end();
            return;
        }
        if (user===undefined){
            resp.status(401).write(JSON.stringify({error:"the user of token not found"}));
            resp.end();
            return;
        }
        user.clearToken(token_req,function(err){
            if (err) {
                resp.status(500);
                resp.write(JSON.stringify({error:"Internal Server Error"}));
                resp.end();
                return;
            }
            resp.status(200).write(JSON.stringify({msg:"Token successfully cleared"}));
            resp.end();
        });
    });
}
function changepassword(req,resp){
    var username_req=req.body.username_req,
        newpassword=req.body.newpassword;
    data.User.findByName(username_req,function(err,user){
        if (err){
            resp.status(500);
            resp.write(JSON.stringify({error:"Internal Server Error"}));
            resp.end();
            return;
        }
        user.setPass(newpassword);
        user.clearallToken(user.data.userid,function (err) {
            if (err){
                resp.status(500);
                resp.write(JSON.stringify({error:"Internal Server Error"}));
                resp.end();
                return;
            }
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
    console.log("validating:"+req.originalUrl);
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
            if (user===undefined) {
                resp.status(401);
                resp.write(JSON.stringify({msg: "Token is invalid or timed out"}));
                resp.end();
                return;
            }
            if(req.originalUrl==="/changepassword"){//修改密码操作
                if (user.data.userid!==1 && user.data.username!==req.body.username_req){
                    resp.status(403);
                    resp.write(JSON.stringify({msg:"Not allowed."}));
                    resp.end();
                    return;
                }
            }
            if (req.originalUrl==="/logout"){ //登出
                if (req.body.token!==req.body.token_req && user.data.userid!==1) {
                    resp.status(403);
                    resp.write(JSON.stringify({msg:"Not allowed."}));
                    resp.end();
                    return;
                }
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
            if (config.debug)
            if (req.)
        }
    ],function (err,result) {
        if (err)
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
    if (newuser.data.username===undefined ||
        newuser.data.username===null||
        plainpass===undefined ||
        plainpass===null){
        resp.status(400).write(JSON.stringify("username or password missing"));
        resp.end();
        return;
    }
    async.series([
        function (callback) {
            newuser.setPass(plainpass,callback);
        },
        function (callback) {
            newuser.save(callback);
        }
    ],function (err,result) {
        if (err) {
            if (err.errno===19){
                //碰到SQL约束
                if (err.message.indexOf("user.username")!==-1){
                    //用户名重名
                    resp.status(409).write(JSON.stringify({error:"username existed"})).end();
                }else{
                    resp.status(500).end();
                }
            }else{
                resp.status(500).end();
            }
        }
        resp.status(200).end();
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
module.exports=router;
exports.querynode=querynode;
exports.addnode=addnode;
exports.delnode=delnode;
