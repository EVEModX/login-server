"use strict";
function login(username,password){
    return new Promise((resolve,reject)=>{
        jQuery.post('./login',{username:"username",password:"password"}).always();
    });
}