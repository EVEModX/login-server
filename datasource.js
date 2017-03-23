/*
* 抽象数据接口,sqlite3版本
* */
var sqlite3=require("sqlite3").verbose();

var debug=require("debug")('datasource');
var crypto=require("crypto");
var config=require("./config");
var async=require("async");
var db=new sqlite3.Database(__dirname+"/test.sqlite3");
db.on('trace',function (stmt) {
    require('debug')('sqlite3')(stmt);
});
/*
* User接口 实现用户数据相关
* */
var User=function (data){
    if (data===undefined || data===null){
        this.data={};
        this.data.username="";
        this.data.password="";
    } else{
        this.data=data;
        this.data.password=new Buffer((this.data.password==null)?"":this.data.password,'hex');
        this.data.password_salt=new Buffer((this.data.password_salt==null)?"":this.data.password_salt,'hex');
    }
};
/*
* User对象字段
* username 用户名 (ASCII)
* userid 用户ID (int)
* nickname 用户显示的昵称 (UTF-8)
* password 存储的密码，和password_salt一起验证 长度32的十六进制字符串
* password_salt 密码盐 长度16字节
* token 存储的用户token
* token_expire 用户token的过期时间
* */
User.data={};
User.prototype.changeNickname=function(newname){
    this.data.nickname=newname;
};

User.findById=function (id,callback) {  //通过ID找到用户
    db.get("SELECT * FROM users WHERE userid=?",id,function(err,row){
        if (err) callback(err);
        if (row===undefined) //没有找到对应用户
            callback(null,undefined);
        callback(null,new User(row));
    });
};
/*
* 通过 username 字段找到用户
* callback(err,user) user:返回的用户对象，找不到返回undefined
* */
User.findByName=function (name,callback){
    db.get("SELECT * FROM users WHERE username=?",name,function(err,row){
        if (err){
            return callback(err);
        }
        if (row===undefined){
            return callback(null,undefined);
        }
        if (new Date(row.expiretime)<new Date()){ //token过期
            db.run("DELETE FROM tokens WHERE token=?",token,function(err) {
                if (err)
                    callback(err);
                else
                    callback(null,undefined);
            });
        }else
            callback(null,new User(row));
    });
};
/*
* 通过已定义的token找到用户
* 如果token过期，将token删除并返回错误
* callback(err,user) user:返回的用户对象，找不到返回undefined
* */
User.findByToken=function (token,callback){
    db.get("SELECT * FROM tokens WHERE token=?",token,function(err,row){
        if (err)
            callback(err);
        else if (row===undefined)
            callback(null,undefined);
        else
            User.findById(row.userid,function(err,user){
                callback(err,user);
            });
    });
};
User.prototype.checkPass=function (plainpass){ //检查password是不是用户的密码
    var password=this.data.password,
        salt=this.data.password_salt;
    var key=crypto.pbkdf2Sync(plainpass,salt,config.security.pbkdf2_iter,16,'sha512');
    return Buffer.compare(password,key)===0;
};
User.prototype.setPass=function (plainpass,callback){  //设置用户密码
    var that=this;
    crypto.randomBytes(16,function (err,buf){
        if (err)
            return callback(err);
        crypto.pbkdf2(plainpass,buf,config.security.pbkdf2_iter,16,'sha512',function (err,key) {
            if (err)
                return callback(err);
            that.data.password=key;
            that.data.password_salt=buf;
            callback(null,true);
        });
    });
};
User.prototype.requireToken=function (expire,callback){ //请求一个用户的token userid:用户ID expire:过期时间(UTC表示)
    var that=this;
    crypto.randomBytes(16,function(err,buf){
        if (err) callback(err);
        db.run("INSERT into tokens (token,expiretime,userid) VALUES(?,?,?)",[buf.toString('hex'),expire,that.data.userid],function(err){
            if (err===null) callback(null,buf);
            else if (err.code==="SQLITE_CONSTRAINT") //有重复的token
                this.requireToken(expire,callback);
            else
                callback(err);
        });
    });
};
User.prototype.clearToken=function (token,callback){ //清除用户的token
    db.run("DELETE FROM tokens WHERE token=?",token,function(err){
        if (err)
            return callback(err);
        else
            return callback(null);
    });
};
User.prototype.clearallToken=function(userid,callback){
    db.run("DELETE FROM tokens WHERE userid=?",userid,function(err){
        if (err)
            return callback(err);
        else
            return callback(null);
    });
};
User.prototype.checkToken=function (token,callback){ //检查这个token是不是属于自己
    var that=this;
    db.get("SELECT * FROM tokens WHERE token=?",token,function(err,row){
        if (err)
            callback(err);
        if (row===undefined) callback(null,false);
        else callback(null,row.userid===that.data.userid);
    });
};
User.prototype.save=function(callback){ //把用户数据写回数据库
    var that=this;
    var db_=new sqlite3.Database(__dirname+"/test.sqlite3");
    db_.on('trace',function (stmt) {
        require('debug')('sqlite3')(stmt);
    });
    async.series([
        function (callback) {
            db_.run("BEGIN IMMEDIATE TRANSACTION",function (err) {
                if (err) callback(err);
                else callback();
            });
        },
        function (callback) {
            if (that.data.userid===undefined || that.data.userid===null && !that.data.username){
                debug('save: insert');
                db_.run("INSERT INTO users(username) VALUES (?)",that.data.username,function (err) {
                    debug('callback on insert');
                    if (err) {debug('error on insert+'+err);callback(err);}
                    else callback();
                });
            }else
                callback();
        },function (callback) {
            async.eachSeries(Object.keys(that.data),function (key,callback2) {
                var val=that.data[key];
                debug('updating '+key);
                if (key==="userid"||key==="username"){//并不能修改的东西
                    return callback2();
                }
                if (key==="password"||key==="password_salt"){
                    val=val.toString('hex');
                }
                db_.run("UPDATE users SET "+key+" = ? WHERE username= ?",[val,that.data.username],function (err) {
                    if (err) callback2(err);
                    else callback2();
                });
            },function (err) {
                if (err) {
                    return callback(err);
                }
                else
                    return callback(null);
            });
        },function (callback) {
            debug('end transaction');
            db_.run("END TRANSACTION",function (err) {
                debug("err"+err);
                if (err) callback(err);
                else callback();
            })
        }
    ],function (err,result) {
        db_.close();
        debug('db_ closed');
        if (err)
        {
            return callback(err);
        }
        else{
            return callback(null);
        }
    });
};
User.prototype.getID=function(){
	return this.data.userid;
};
exports.User=User;
