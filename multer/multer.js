const multer=require("multer");
const memmoryStorage=multer.memoryStorage();

//diskStorage
const storage=multer.diskStorage({
    destination:(req,file,cb)=>{
        cb(null,"./uploads");
    },
    filename:(req,file,cb)=>{
        let filename=`${Date.now()}.${file.originalname}`
        cb(null,filename); // null means we can define error here if any
    }
});
const fileFilter=(req,file,cb)=>{
    if(file.mimetype==="image/png"||file.mimetype==="image/jpeg" || file.mimetype==="image/jpg"||file.size<184655){
        cb(null,true)
    }else{
        cb(new Error("file type is not valid or invalid size "),false);
    }
}
const upload=multer({
    storage:storage,
    fileFilter:fileFilter
    // memmoryStorage:memmoryStorage
});

module.exports=upload