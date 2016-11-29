/* Use UTF-8 to operate this file*/
/*
* 网站配置文件
* */
var config={};
config.server={};
config.server.listenport= process.env.WEB_PORT || 8080; // web server 监听端口

config.security={};
config.security.tokenLivetime=60*60*24*3; //秒

module.exports=config;