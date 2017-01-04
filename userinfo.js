/**
 * Created by byr on 2016/12/5.
 */
/*
* 用户信息处理模块
* */
var express=require("express");
var data=require("./datasource");
var router=express.Router();

/*
* 获取用户信息
* */
function getUserinfo(req,resp){
    var requsername=req.body.username_req;
    data.User.findByName(requsername,function (err,user) {
        if (err){
            resp.status(500);
            resp.end();
            return;
        }
        if (user===undefined){
            resp.status(404).write(JSON.stringify({error:"User not found"}));
            resp.end();
            return;
        }
        var userinfo={};
        userinfo.username=user.data.username;
        userinfo.nickname=user.data.nickname;
        userinfo.userid=user.data.userid;
        resp.status(200).write(JSON.stringify(userinfo));
        resp.end();
    });
}
function setUserinfo(req,resp){
    var requsername=req.body.username_req,
        newinfo=req.body.newinfo;
    data.User.findByName(requsername,function (err,user){
        if (err){
            resp.status(500);
            resp.end();
            return;
        }
        if (user===undefined){
            resp.status(404).write(JSON.stringify({error:"User not found"}));
            resp.end();
            return;
        }
        newinfo=JSON.parse(newinfo);
        user.data.nickname=newinfo.nickname;
        resp.status(204).end();
    });
}
router.post('/getinfo',getUserinfo);
router.post('/setinfo',setUserinfo);
module.exports=router;