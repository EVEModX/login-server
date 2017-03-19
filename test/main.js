//encoding:utf-8
/*
* 主测试模块
* */
var app=require('../app');
var request=require('supertest')('http://localhost:8080');
var should=require('should');

describe('main.js',function () {
    var loginname="root",password="root",token,token2;
    describe('static-module',function () {
        it('should send correct static contents',function (done) {
            request.get('/')
                .expect('Content-Type',/text/)
                .expect(302,done);
        });
    });
    describe('login',function () {
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
    });
});