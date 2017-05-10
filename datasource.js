/*
* 抽象数据接口,sqlite3版本
* */
const sqlite3=require("sqlite3").verbose();
const _=require('lodash');
const debug=require("debug")('datasource');
const crypto=require("crypto");
const config=require("./config");
const async=require("async");
let db=new sqlite3.Database(__dirname+"/test.sqlite3");
db.on('trace',function (stmt) {
    require('debug')('sqlite3')(stmt);
});
/*
* User接口 实现用户数据相关
* */
function User(data){
    if (data===undefined || data===null){ //创建一个新用户(自然也不会有username/password)
        this.data={};
        this.data.username="";
        this.data.password="";
    } else{
        this.data=data;
        this.data.password=new Buffer((this.data.password==null)?"":this.data.password,'hex');
        this.data.password_salt=new Buffer((this.data.password_salt==null)?"":this.data.password_salt,'hex');
    }
}
/*
* User对象字段
* username string 用户名
* userid int 用户ID
* nickname string 用户显示的昵称
* password Buffer(16) 存储的密码hash
* password_salt Buffer(16) 密码盐
*
* User只管理最基本的鉴权，包括后期的2FA都不管，另外写模块处理
* */
/*
* 根据ID找到用户
* @param id
* @callback 回调函数
* */
User.findById=function (id,callback) {
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
/*
 * 修改用户昵称 sync
 * @param name string 新的用户昵称
 * */
User.prototype.setNickname=function (name) {
        this.data.nickname=name;
};
/*
* 检查密码是否匹配 sync
* @param plainpass string 明文密码
* @return boolean 返回密码比对结果
* */
User.prototype.checkPass=function (plainpass){
    let password=this.data.password,
        salt=this.data.password_salt;
    let key=crypto.pbkdf2Sync(plainpass,salt,config.security.pbkdf2_iter,16,'sha512');
    return Buffer.compare(password,key)===0;
};
/*
* 设置用户密码
* @param plainpass string 明文密码
* @callback err:错误
* */
User.prototype.setPass=function (plainpass,callback){
    var that=this;
    crypto.randomBytes(16,function (err,buf){
        if (err)
            return callback(err);
        crypto.pbkdf2(plainpass,buf,config.security.pbkdf2_iter,16,'sha512',function (err,key) {
            if (err)
                return callback(err);
            that.data.password=key;
            that.data.password_salt=buf;
            callback(null);
        });
    });
};
/*
* 请求一个 token
* @param expire int64 请求的过期时间 (UNIX timestamp)
* @callback err:错误 token:返回的token(Buffer)
* */
User.prototype.requireToken=function (expire,callback){
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
/*
* 注销某个token
* @param token string 要被注销的token
* @callback err:错误
* */
User.clearToken=function (token,callback){
    db.run("DELETE FROM tokens WHERE token=?",token,function(err){
        if (err)
            return callback(err);
        else
            return callback(null);
    });
};
/*
* 注销某个userid所代表用户的所有 token
* @param userid int 用户ID
* @callback err:错误
* */
User.clearAllToken=function(userid, callback){
    db.run("DELETE FROM tokens WHERE userid=?",userid,function(err){
        if (err)
            return callback(err);
        else
            return callback(null);
    });
};
/*
* 获取当前用户ID
* @return int 当前用户ID
* */
User.prototype.getID=function(){
    return this.data.userid;
};
/*
* save 将用户数据写回数据库
* */
User.prototype.save=function(callback){ //把用户数据写回数据库
    let that=this;
    let db_=new sqlite3.Database(__dirname+"/test.sqlite3");
    db_.on('trace',function (stmt) {
        require('debug')('sqlite3')(stmt);
    });
    async.series([
        function (callback) {
            db_.run("PRAGMA journal_mode = WAL;");
            db_.configure('busyTimeout',100000);
            callback();
        },
        function (callback) {
            db_.run("BEGIN TRANSACTION",function (err) {
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
                let val=that.data[key];
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
    ],function (err) {
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
exports.Authorize={
    /*
    * 处理授权相关的查询
    * */
    /*
    * 数据库表名
    * 表结构
    * role varchar 角色 类似 "<module>.<id>"
    * resource varchar 资源
    * action varchar 动作
    * perm boolean 是否允许 目前阶段此字段保持为1(允许)
    * CONSTRAINT permission UNIQUE (role,resource,action) ON CONFLICT REPLACE
    * */
    TABLE_NAME:"privileges",
    /*
    * 设置权限记录
    * @param role string 角色
    * @param resource string 资源
    * @param action string 动作
    * @callback err:错误
    *
    * */
    setPermission:function (role,resource,action,callback) {
        "use strict";
        let perm=true;
        if (_.isEmpty(role) || _.isEmpty(resource) || _.isEmpty(action))
            return callback(new Error("args cannot be empty"));
        db.run("INSERT INTO "+this.TABLE_NAME+" (role,resource,action,perm)" +
            " VALUES(?,?,?,?)",[role,resource,action,perm],function (err,result) {
            if (err) return callback(err);
            else callback(null);
        });
    },
    /*删除权限记录 (单点)*/
    delPermission:function (role,resource,action,callback) {
        "use strict";
        if (_.isEmpty(role) || _.isEmpty(resource) || _.isEmpty(action))
            return callback(new Error("args cannot be empty"));
        db.run("DELETE FROM "+this.TABLE_NAME+
            " WHERE role LIKE ? AND resource LIKE ? AND action LIKE ?",[role,resource,action], function (err,result) {
            if (err) return callback(err);
            else return callback(null);
        });
    },
    /*
    * 查询权限记录
    * @callback err:错误 result: perm字段的返回值，未找到返回 undefined
    * */
    getPermission:function (role, resource, action, callback) {
        "use strict";
        if (_.isEmpty(role) || _.isEmpty(resource) || _.isEmpty(action))
            return callback(new Error("args cannot be empty"));
        db.get("SELECT perm FROM "+this.TABLE_NAME+" WHERE role=? AND resource=? AND action=?",[role,resource,action],function (err,result) {
            if (err) return callback(err);
            return callback(null,(result===undefined)?undefined:result.perm);
        });
    }
};
exports.User=User;
