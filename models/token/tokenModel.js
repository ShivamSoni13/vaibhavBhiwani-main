const mongoose=require("mongoose");
const userModel = require("../registerUser/registerUser");

const TokenSchema=new mongoose.Schema({
    userId:{
        type:mongoose.Schema.ObjectId,
        ref:"userModel",
       
    },
    token:{
        type:String,
        required:true
    },
    createdAt:{
        type:Date,
        default:Date.now,
        expires:3600
        
    }
});

const tokenModel=new mongoose.model("tokenData",TokenSchema);
module.exports=tokenModel;