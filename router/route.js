import { Router } from "express";
const router = Router();

//  import all controllers
import * as controller from "../controllers/appController.js";
import { registerMail } from "../controllers/mailer.js";
import Auth, { localVariables } from "../middleware/auth.js";

// POST METHODS
// AUTH
router.route("/register").post(controller.register); // register user
router.route("/registerMail").post(registerMail); // send the email
router
  .route("/autenticate")
  .post(controller.verifyUser, (req, res) => res.end()); // authenticate user
router.route("/login").post(controller.verifyUser, controller.login); // login in app
// POSTS
router.route("/createPost").post(controller.verifyUser, controller.createPost); // created posts
router
  .route("/createComment")
  .post(controller.verifyUser, controller.createComment); // created comments

// GET METHODS
// AUTH
router.route("/user").get(controller.getUser); // user with response
router.route("/generateOTP").get(controller.generateOTP); // generate random OTP
router.route("/verifyOTP").get(controller.verifyOTP); // verify generate OTP
router.route("/createResetSession").get(controller.createResetSession); // reset all the variables
router.route("/posts").get(controller.getPosts); // posts with response
router.route("/comments").get(controller.getComments); // posts with response
router.route("/searchUsers").get(controller.searchUsers);

// PUT METHODS
// AUTH
router.route("/updateuser").put(Auth, controller.updateUser); // is used to update the user profile
router
  .route("/resetPassword")
  .put(controller.verifyUser, controller.resetPassword); // is used to reset password
router.route("/likeComment").put(Auth, controller.likeComment); // is used to update the user profile
router.route("/followUser").put(Auth, controller.followUser); // is used to update the user profile

export default router;
