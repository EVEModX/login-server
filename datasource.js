/*
* 抽象数据接口,sqlite3版本
* */
var sqlite3=require("sqlite3");
var crypto=require("crypto");
var config=require("./config");
var db=new sqlite3.Database(__dirname+"/test.sqlite3");
/*
* User接口 实现用户数据相关
* */
var User=function (data){
    this.data=data;
    this.data.password=new Buffer(this.data.password,'hex');
    this.data.password_salt=new Buffer(this.data.password_salt,'hex');
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
    var stmt=db.prepare("SELECT * FROM users WHERE userid=(?)");
    stmt.get(id,function(err,row){
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
    var stmt=db.prepare("SELECT * FROM users WHERE username=(?)");
    stmt.get(name,function(err,row){
        if (err)
            return callback(err);
        if (row===undefined)
            return callback(null,undefined);
        if (new Date(row.expiretime)<new Date()){ //token过期
            db.run("DELETE FROM tokens WHERE token=?",token,function(err) {
                if (err)
                    callback(err);
                callback(null,undefined);
            });
        }
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
            return callback(err);
        if (row===undefined)
            return callback(null,undefined);
        User.findById(row.userid,function(err,user){
            return callback(err,user);
        });
    });
};
User.prototype.checkPass=function (plainpass){ //检查password是不是用户的密码
    var password=this.data.password,
        salt=this.data.password_salt;
    crypto.pbkdf2(plainpass,salt,config.security.pbkdf2_iter,16,'sha512',function(err,key){
        if (err)
            throw err;
        return key === password;
    });
};
User.prototype.setPass=function (plainpass){  //设置用户密码
    var that=this;
    crypto.randomBytes(16,function (err,buf){
        if (err)
            throw err;
        crypto.pbkdf2(plainpass,buf,config.security.pbkdf2_iter,16,'sha512',function (err,key) {
            if (err)
                throw err;
            that.data.password=key;
            that.data.password_salt=buf;
            return true;
        });
    });
};
User.prototype.requireToken=function (expire,callback){ //请求一个用户的token userid:用户ID expire:过期时间(UTC表示)
    var that=this;
    crypto.randomBytes(16,function(err,buf){
        if (err) return callback(err);
        db.run("INSERT into tokens (token,expiretime,userid) VALUES(?,?,?)",[buf.toString('hex'),expire,that.data.userid],function(err){
            if (err===null) return callback(null,buf);
            if (err.code==="SQLITE_CONSTRAINT") //有重复的token
                return this.requireToken(expire,callback);
            else
                callback(err);
        });
    });
};
User.prototype.clearToken=function (token){ //清除用户的token
    db.run("DELETE FROM tokens WHERE token=?",token,function(err){
        if (err)
            throw err;
    });
};
User.prototype.clearallToken=function(userid){
    db.run("DELETE FROM tokens WHERE userid=?",userid,function(err){
        if (err)
            throw err;
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
User.prototype.save=function(){ //把用户数据写回数据库
    db.run("BEGIN TRANSACTION");
    var keys=Object.keys(this.data);
    for (var i=0;i<keys.length;++i){
        var key=keys[i];
        var val=this.data[key];
        if (key==="userid" || key==="username")
            continue;
        if (key==="password" || key==="password_salt")
            val=val.toString('hex');
        db.run("UPDATE users SET "+key+" = ? WHERE userid= ?",[val,this.data.userid],function (err) {
            if (err)
                console.log(err);
        });
    }
    db.run("END");
};
exports.User=User;
