/* Use UTF-8 to operate this file*/
/*
 * 网站配置文件
 * */
"use strict";
let config={};
//开发设置
config.debug=true;
//服务器设置
config.server={};
config.server.listenport= process.env.WEB_PORT || 8080; // web server 监听端口
//安全相关配置
config.security={};
config.security.tokenLivetime=60*60*24*3; //秒
config.security.pbkdf2_iter=20000; //数据库一旦初始化不可更改
//redis 配置
config.redis={};
config.redis.port=6379;
config.mysql={};
config.mysql.host="localhost";
config.mysql.port=3306;
config.mysql.user="root";
config.mysql.password="root";
config.mysql.database="login-server";
module.exports=config;