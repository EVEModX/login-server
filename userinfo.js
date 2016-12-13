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
            resp.writeHead(500);
            resp.end();
            return;
        }
        resp.type("json");
        resp.writeHead(200).json(user);
    });
}
router.post('/getinfo',getUserinfo);
module.exports=router;