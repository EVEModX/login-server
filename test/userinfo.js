let app=require('../app');
const request=require('supertest')('http://localhost:8080');
const should=require('should');
const debug = require('debug')('test');
const sqlite3 = require('sqlite3');
const async = require("async");
describe('userinfo Module',function () {
    before('init user',function (done) {

    });
});