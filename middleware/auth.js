const jwt=require("jsonwebtoken");
exports.loginAuth=async(req,res,next)=>{
    try{
        const token=req.cookies.vaibhavBhiwaniCookie;
        if(token){
                const verifyToken=await jwt.verify(token,process.env.SECRETKEY);
                req.user=verifyToken._id;
                next();
        }else{
            res.status(401).json({message:"token not found or expired please try to login again",success:false});
        }
        
    }catch(error){
        res.status(400).json({error:error,success:false})
    }
   
}