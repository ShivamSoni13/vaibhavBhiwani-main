const userModel = require("../models/registerUser/registerUser")

exports.adminAuth=async(req,res,next)=>{
   try{
    const loginUser=await userModel.find({_id:req.user});
    if(loginUser[0].isAdmin){
        next();
    }else{
        res.status(401).json({message:"only admin can accecss it ,try to login with admin ",success:false});
    }
   }catch(error){
    res.status(400).json({error:error,success:false});
   }
}