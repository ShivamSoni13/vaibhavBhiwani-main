const mongoose = require("mongoose");
const validator=require('validator');
const bcryptjs=require("bcryptjs");
const jwt=require("jsonwebtoken");

const registerUserSchema=new mongoose.Schema({
  avatar:{
    public_id:{
      type:String,
      required:[true,"please enter valid public_id of the image"]
    },
    url:{
      type:String,
      required:[true,"please provide valid url path"]
    }
  },
  name: {
    type: String,
    required: [true, "Please enter you name"],
  },
  email: {
    type: String,
    unique:[true,"please entered unique email"],
    validate:[validator.isEmail,"please enter valid email address"],
    required: [true, " please enter email "],
  },
  phoneNumber:{
    type:String,
    required:[true,"please enter your phone Number"]
  },
  passWord: {
    type: String,
    required: [true, "please Enter passWord"],
  },
  rePassWord:{
    type:String,
    required:[true,"please enter rePassword"]
  },
  tokens:[
    {
      token:{
        type: String,
      }
    }
  ],
  isAdmin:{
    type:Boolean,
    default:false
  },
  createdAt:{
    type:Date,
    default:Date.now
  }
});

//hashed the passWord on event "save" 
registerUserSchema.pre("save", async function (next) {
  if (this.isModified("passWord")) {
    this.passWord = await bcryptjs.hash(this.passWord, 10);
  }
  if (this.isModified("rePassWord")) {
    this.rePassWord = await bcryptjs.hash(this.rePassWord, 10);
  }
  next();
});


registerUserSchema.methods.getJwtToken= function(){
  const token =  jwt.sign({_id:this._id},process.env.SECRETKEY,{
    expiresIn:"2d",
  }); 
  this.tokens=this.tokens.concat({token:token});
  this.save();
  return token;
}


const userModel=new mongoose.model("registerUserSchema",registerUserSchema); 
module.exports=userModel;
