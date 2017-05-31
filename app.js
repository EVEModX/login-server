/* Use UTF-8 to operate this file*/
"use strict";
const express=require('express');
const bodyParser=require('body-parser');
const auth=require('./authentication');
const userinfo=require("./userinfo");
const cfg=require('./config');
const accounts=require('./accounts');
const ExpBrute=require('express-brute');
let app=express();

app.use(bodyParser.json()); //支持 JSON 主体
app.use(bodyParser.urlencoded({extended:true})); // 支持 URL 编码主体

let store=new ExpBrute.MemoryStore();
let expbrute=new ExpBrute(store,{
    freeRetries:20,
    minWait:2000,
    lifetime:3600,
    failCallback:ExpBrute.FailForbidden,
});
if (process.env.BRUTEFORCE==="yes"){
    console.log('enabled brute force protection');
    app.use(expbrute.getMiddleware({
        key:"token"
    }));
}
app.use(auth); //所有请求全部要检查权限，同时把权限相关的请求处理掉
app.use('/user',userinfo); //用户信息模块
app.use('/accounts',accounts);
app.get('/',function (req,res) {
    res.redirect("/index.html"); //前面的都不抓就返回index.html
});
app.use(express.static('static')); //前面的都不抓说明请求的静态文件，返回
/*app.use(function (err,req,res,next) { //兜底错误处理，防止node崩溃
    res.status(500).send({error:"unknown error occurred, please contact admin."});
    console.error(err);
});*/
app.listen(cfg.server.listenport,function(){
    console.log("Server Started");
});
