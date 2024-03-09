const express = require("express");
const {
  registerUser,
  loginUser,
  userLogout,
  tryMulter,
  tokenCtrl,
  resetPassWord,
  particularUserDetails,
  updateUserPassWord,
  profileUpdate,
  getUserDataForAdmin,
  particularUserDetialsForAdmin,
  updateIsAdminRole,
  deleteParticularUser,
} = require("../controllers/userCtrl");
const upload = require("../multer/multer");
const { loginAuth } = require("../middleware/auth");
const { adminAuth } = require("../middleware/adminauth");
const userRouter = express.Router();

//register user router

//post user detalis router
userRouter.post("/registerUser", registerUser);
//login api
userRouter.post("/loginUser", loginUser);
//logout api
userRouter.get("/userLogout", userLogout);
//token storing and send Email routing for password reset.
userRouter.post("/tokenReset", tokenCtrl);
//update password behalf on above sending url
userRouter.put("/passWord-reset/:_id/:token", resetPassWord);
//find full details of login User to show user his profile
userRouter.get("/particularUserDetails", loginAuth, particularUserDetails);
//updateUser passWord --user
userRouter.put("/updateUserPassWord", loginAuth, updateUserPassWord);
//profile update like name and emails
userRouter.put("/profileUpdate", loginAuth, profileUpdate);
//get all user data for --admin
userRouter.get(
  "/getUserDataForAdmin",
  loginAuth,
  adminAuth,
  getUserDataForAdmin
);
//get Particular user details for --admin
userRouter.get(
  "/particularUserDetialsForAdmin/:_id",
  loginAuth,
  adminAuth,
  particularUserDetialsForAdmin
);
//update user isAdmin role --admin
userRouter.put(
  "/updateIsAdminRole/:_id",
  loginAuth,
  adminAuth,
  updateIsAdminRole
);
//delete Partocular user by --admin
userRouter.delete(
  "/deleteParticularUser/:_id",
  loginAuth,
  adminAuth,
  deleteParticularUser
);

//multer
// userRouter.post("/multer",upload.single("image"),tryMulter);

module.exports = userRouter;  
