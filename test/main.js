//encoding:utf-8
/*
* 主测试模块
* */
var app=require('../app');
var request=require('supertest')('http://localhost:8080');
var should=require('should');
var sqlite3=require('sqlite3');
var redis=require('redis'),
    rdsclient=redis.createClient();
var async = require("async");

describe('main.js',function () {
    var loginname="root",password="root",token,token2;
    before('init database',function(done){
        var db=new sqlite3.Database(__dirname+"/../test.sqlite3");
        db.run("DELETE FROM tokens",function () {
            db.run("DELETE FROM users WHERE NOT username=\'root\'",function (err) {
                if (err) throw err;
                db.close(done);
            });
        });
    });
    describe('static-module',function () {
        it('should send correct static contents',function (done) {
            request.get('/')
                .expect('Content-Type',/text/)
                .expect(302,done);
        });
        it('should send correct static pictures --pending');
    });
    describe("users' accounts",function () {
        it('should not sign in when username is empty',function (done) {
            request.post('/login')
               .type('form')
               .send({password:password})
               .expect(401,done);
        });
        it('should not sign in when password is empty',function (done) {
            request.post('/login')
               .type('form')
               .send({username:loginname})
               .expect(401,done);
        });
        it('should not sign in when user/password is wrong',function (done) {
            request.post('/login')
               .type('form')
               .send({username:'233',password:'233'})
               .expect(401,done);
        });
        it('should not crash when login type is wrong',function (done) {
            request.post('/login')
               .type('form')
               .send({username:233,password:233})
               .expect(401,done);
        });
        it('should sign in when user/password is right',function (done) {
            request.post('/login')
               .type('form')
               .send({username:loginname,password:password})
               .expect(function (res) {
                   res=JSON.parse(res.text);
                   token=res.token;
               })
               .expect(200,done);
        });
        it('should renew token when token is right',function (done) {
            request.post('/renew')
               .type('form')
               .send({token:token})
               .expect(function (res) {
                   res=JSON.parse(res.text);
                   token2=res.token;
                   console.log("token2 is "+token2);
               })
               .expect(200,done);
        });
        it('should revoke the old token',function (done) {
            request.post('/renew')
               .send({token:token})
               .expect(401,done);
        });
        it('should not renew token when token is null',function (done) {
            request.post('/renew')
               .send({token:null})
               .expect(401,done);
        });
        it('should not renew token when token is numeric',function (done) {
            request.post('/renew')
               .send({token:233})
               .expect(401,done);
        });
        it('should not logout with wrong token',function (done) {
            request.post('/logout')
               .send({token:token,token_req:token})
               .expect(401,done);
        });
        it('should not logout with empty',function (done) {
            request.post('/logout')
                .send({token:token2})
                .expect(401,done);
        });
        it('should not logout with numeric token',function (done) {
            request.post('/logout')
               .send({token:token2,token_req:233})
               .expect(401,done);
        });
        it('should successfully logout',function (done) {
            request.post('/logout')
               .send({token:token2,token_req:token2})
               .expect(200,done);
        });
        var addusers=[];
        it('should add user',function (done) {
            request.post('/login')
                .send({username:loginname,password:password})
                .expect(function (res) {
                    res=JSON.parse(res.text);
                    token=res.token;
                    addusers=[
                        {name:"with null nickname",args:{token:token,username:"test2",password:"test2"},expected:200},
                        {name:"without existed username",args:{token:token,username:"test2",password:"test2"},expected:409},
                        {name:"without null pass",args:{token:token,username:"test3",password:""},expected:400},
                        {name:"without null username",args:{token:token,username:"",password:"test4"},expected:400},
                        {name:"without blank username",args:{token:token,username:"    ",password:"test5"},expected:400},
                        {name:"without whitespaces",args:{token:token,username:"tes t5",password:"Test5"},expected:400}
                    ];
                })
                .expect(200,function (err) {
                    if (err) throw err;
                    request.post('/adduser')
                        .send({token:token,username:"test1",password:"test1",nickname:"test1"})
                        .expect(200,done);
                });
        });
        addusers.forEach(function (test) {
            it('should add user '+test.name,function (done) {
                request.post('/adduser')
                   .send(test.args)
                   .expect(test.expected,done);
            });
        });
        var test1Token,test1ID;
        it('should login the new user',function (done) {
            request.post('/login')
                .send({username:"test1",password:"test1"})
                .expect(function (res) {
                    res=JSON.parse(res.text);
                    test1Token=res.token;
                    test1ID=res.userid;
                })
                .expect(200,done);
        });
        it('should change password',function (done) {
            request.post('/changepassword')
                .send({token:test1Token,userid:test1ID,newpassword:"t1"})
                .expect(200,done);
        });
        it('should revoke token after password changed',function (done) {
            request.post('/renew')
                .send({token:test1Token})
                .expect(401,done);
        });
        it('should changed password',function (done) {
            request.post('/login')
                .send({username:"test1",password:"t1"})
                .expect(function (res) {
                    res=JSON.parse(res.text);
                    test1Token=res.token;
                })
                .expect(200,function (err) {
                    if (err) throw err;
                    request.post('/login')
                        .send({username:"test1",password:"test1"})
                        .expect(401,done);
                });
        });
        it('should not change other\'s password',function (done) {
            request.post('/changepassword')
                .send({token:test1Token,userid:0,newpassword:"root1"})
                .expect(403,done);
        });
    });
    describe('accounts module',function () {
        var tokens=[];
        var roottoken;
        var users=[{username:"pibc",password:"pibc"},{username:"tga",password:"tga"},{username:"fbp",password:"fbp"}];
        var db=new sqlite3.Database(__dirname+"/../test.sqlite3");
        before('clear all accounts and privileges',function (done) {
            async.series([
                function (cb) {
                    db.run("DELETE FROM tokens",function (err) {
                        if (err) cb(err);
                        db.run("DELETE FROM users WHERE NOT username=\'root\'",function (err) {
                            if (err) cb(err);
                            db.close(cb);
                        });
                    })
                },
                function (cb) {
                    rdsclient.flushall(cb);
                },
                function (cb) {
                    request.post('/login').send({username:"root",password:"root"})
                        .expect(function (res) {
                            res=JSON.parse(res.text);
                            roottoken=res.token;
                        }).expect(200,cb);
                },
                function (cb) {
                    async.each(users,function (user,cb2) {
                        request.post('/adduser').send(Object.assign({token:roottoken},user))
                            .expect(200,cb2);
                    },cb);
                },
                function (cb) {
                    async.each(users,function (user,cb2) {
                        request.post('/login').send(user)
                            .expect(function (res) {
                                res=JSON.parse(res.text);
                                tokens.push(res.token);
                            }).expect(200,cb2);
                    },cb);
                }
            ],function (err,res) {
                if (err) throw err;
                done();
            });
        });
        it('should add eve account',function (done) {
            request.post('/accounts/add').send({token:tokens[0],account:"{username:test,password:test}"})
                .expect(200,done);
        });
        it('should get eve account');
    });
    describe('userinfo module',function () {

    });
});