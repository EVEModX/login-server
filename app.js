/* Use UTF-8 to operate this file*/
var express=require('express');
var bodyParser=require('body-parser');
var auth=require('./authentication');
var cfg=require('./config');
var app=express();

app.use(bodyParser.json()); //支持 JSON 主体
app.use(bodyParser.urlencoded({extended:true})); // 支持 URL 编码主体
app.use(auth); //所有请求全部要检查权限，同时把权限相关的请求处理掉
app.get('/',function (req,res) {
    res.redirect("/index.html"); //前面的都不抓就返回index.html
});
app.use(express.static(__dirname+'/static')); //前面的都不抓说明请求的静态文件，返回
app.listen(cfg.server.listenport,function(){
    console.log("Server Started");
});
