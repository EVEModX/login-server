/*
* 抽象数据接口,sqlite3版本
* */
var sqlite=require("sqlite3");
var db=sqlite3.Database(__dirname+"/test.sqlite3");
/*
* User接口 实现用户数据相关
* */
var User=function (data){
    this.data=data;
};
User.prototype.data={};
User.prototype.changeNickname=function(newname){
    this.data.nickname=newname;
};
User.prototype.save=function(callback){ //把用户数据写回数据库

};

User.findById=function (id,callback) {  //通过ID找到用户
    var stmt=db.prepare("SELECT * FROM users WHERE id=(?)");
    stmt.get(id,function(err,row){
        if (err) callback(err);
        //TODO:新建一个User实例，把数据弄进这个实例
        if (row===undefined) //没用找到对应用户
            callback();//TODO:告诉callback没有对应用户
        callback(null,new User(row));
    });
};
/*
* 通过 username 字段找到用户
* callback(err,user): user:返回的用户对象，找不到返回undefined
* */
User.findByName=function (name,callback){
    var stmt=db.prepare("SELECT * FROM users WHERE username=(?)");
    stmt.get(name,function(err,row){

    });
};
/*User.findByToken=function (token,callback){
    var stmt=db.prepare("SELECT * FROM tokens WHERE id=(?)");
    stmt.get(token,function(err,row){
        if (err) callback(err);
        if (row===undefined)
            callback();
        callback(null,new User(row));
    });
};*/
User.checkPass=function (password){ //检查password是不是用户的密码，只做同步
    //TODO:实现
};
User.setToken=function (token,expire,callback){ //设定用户的token token:token expire:过期时间(UTC表示) callback(err)
    //TODO:实现
};
User.clearToken=function (callback){ //清除用户的token
    //TODO:实现
};
User.checkToken=function (token){ //检查用户是否有这个token，返回 True/False 同步函数
    //TODO:实现
};
User.save=function (callback){ //将用户信息写回数据库
    //TODO:实现
};
exports.User=User;
