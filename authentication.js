/* Use UTF-8 to operate this file*/
/*
 * 此模块处理权限相关问题，包括获取token、更改密码、更改权限之类
 * */
var express=require('express');
var crypto=require('crypto');
var data=require('./datasource');
var config = require("./config.js");
var debug=require('debug');
var redis=require('redis'),
    rdsclient=redis.createClient();
rdsclient.on("error",function (err) {
    console.log("REDIS CLIENT ERROR:"+err);
});
var router=express.Router();
/*
* login() 对req里面存在的登录请求做出反应
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
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够
                    if (err) throw (err);
                    var expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime;
                    user.requireToken(expiretime,function(err,token){
                        if (err) throw (err);
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
        resp.status(500);
        resp.write(JSON.stringify({error:"operation not implemented."}));
        resp.end();
    }
}
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
* 检查request的权限是否正确
* @deprecated 权限系统需要重写
* */
function validate(req,resp,next){
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
            next();
            //TODO:实现检查用户的权限和各个操作所需要的权限比对
        });
    }
}
/*
* 查询节点
* :param id 用户ID
* :param priv 权限节点
* :param callback 回调
* */
function querynode(id,priv,callback){
    rdsclient.sismember(priv,id,function (err,reply) {
        if (err) {callback(err);return;}
        callback(null,reply===1);
    });
}
/*
* 添加权限节点
* :param id 用户ID
* :param priv 权限节点
* :param callback 回调
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
router.use(validate); //
router.post('/login',login);
router.post('/renew',login);
router.post('/logout',logout);
router.post('/changepassword',changepassword);
module.exports=router;
