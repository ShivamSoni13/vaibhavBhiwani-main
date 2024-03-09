const express=require("express");
const { postProducts,getAllproducts,updateProducts,deleteProduct,getSingleProducts, reviewSystem } = require("../controllers/productsCtrl");
const { loginAuth } = require("../middleware/auth");
const { adminAuth } = require("../middleware/adminauth");
const router=express.Router();

//store the product --admin
router.post("/postProduct",loginAuth,adminAuth,postProducts);
//getAllProducts --Alluser
router.get("/getAllproducts",getAllproducts);
//get single products by id  --AllUsers
router.get("/getSingleProducts/:_id",getSingleProducts);
//update the product
router.put("/updateProducts/:_id",loginAuth,adminAuth,updateProducts);
//delete the products api --admin
router.delete("/deleteProduct/:_id",loginAuth,adminAuth,deleteProduct);
//product review system
router.put("/reviewSystem/:_id",loginAuth,reviewSystem);



module.exports=router;