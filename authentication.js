/* Use UTF-8 to operate this file*/
/*
 * 此模块处理权限相关问题，包括获取token、更改密码、更改权限之类
 * */
var express=require('express');
var crypto=require('crypto');
var data=require('./datasource');
var config = require("./config.js");
var debug=require('debug');
var router=express.Router();
/*
* login() 对req里面存在的登录请求做出反应
* */
function login(req,resp){ //负责给新的token，包括续期token
    var username=req.body.username,
        password=req.body.password,
        token=req.body.token;
    if (req.baseUrl==="/login"){ //登录
        data.User.findByName(username,function (err,user){
            if (err) throw err;
            if (user!==undefined && user.checkPass(password)) {
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够
                    if (err) throw (err);
                    var expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime;
                    user.setToken(buf,expiretime,function(err){
                        if (err) throw (err);
                        resp.writeHead(200).json({token:token,expiretime:expiretime});
                        resp.end();
                    });
                });
            }else{
                resp.writeHead(403).json({error:"username and password mismatch"});
                resp.type("json");
            }
        });
    }
    else if (req.baseUrl==="/renew"){ //续期token
        data.User.findByName(username,function (err,user){
            if (err) throw err;
            if (user!==undefined && user.checkToken(token)){
                crypto.randomBytes(8,function(err,buf){ //64bit token 应该足够
                    if (err) throw (err);
                    var expiretime=Math.floor(Date.now() / 1000)+config.security.tokenLivetime
                    user.setToken(buf,expiretime,function(err){
                        if (err) throw (err);
                        resp.writeHead(200).json({token:token,expiretime:expiretime});
                        resp.end();
                    });
                });
            }else{
                resp.writeHead(403).json({error:"Token is invalid"});
                resp.end();
            }
        });
    }
}
function logout(req,resp) { //实质为注销token
    var username=req.body.username,
        token=req.body.token;
    data.User.findByName(username,function(err,user){
        if (err) throw err;
        if (user===undefined || !user.checkToken(token)){
            resp.writeHead(403).json({error:"Token is invalid"});
            resp.end();
            return;
        }
        user.clearToken(function(err){
            if (err) throw err;
            resp.writeHead(200).json({msg:"Token successfully cleared"});
            resp.end();
        });
    });
}
function changepassword(req,resp){
    //TODO:实现
}
function validate(req,resp,next){ //检查request的权限是否正确
    var token=req.body.token;
    console.log("validating:"+req.originalUrl);
    console.log("DEBUG:"+req.originalUrl.endsWith(".html"));
    if (req.originalUrl==="/login") next(); //登录请求不检查
    else if (req.originalUrl==="/") next();
    else if (req.originalUrl.endsWith(".html")) next();
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
            if (user===undefined){
                resp.status(403);
                resp.write(JSON.stringify({msg:"Token is invalid or timed out"}));
                resp.end();
            }
            else
                next();
            //TODO:实现检查用户的权限和各个操作所需要的权限比对
        });
    }
}
router.use(validate); //
router.post('/login',login);
router.post('/logout',logout);
router.post('/renew',login);
router.post('/changepassword',changepassword);
module.exports=router;
