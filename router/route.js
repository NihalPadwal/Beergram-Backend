import { Router } from "express";
const router = Router();

//  import all controllers
import * as controller from "../controllers/appController.js";
import { registerMail } from "../controllers/mailer.js";
import Auth, { localVariables } from "../middleware/auth.js";

// POST METHODS
router.route("/register").post(controller.register); // register user
router.route("/registerMail").post(registerMail); // send the email
router
  .route("/autenticate")
  .post(controller.verifyUser, (req, res) => res.end()); // authenticate user
router.route("/login").post(controller.verifyUser, controller.login); // login in app

// GET METHODS
router.route("/user").get(controller.getUser); // user with response
router.route("/generateOTP").get(controller.generateOTP); // generate random OTP
router.route("/verifyOTP").get(controller.verifyOTP); // verify generate OTP
router.route("/createResetSession").get(controller.createResetSession); // reset all the variables

// PUT METHODS
router.route("/updateuser").put(Auth, controller.updateUser); // is used to update the user profile
router
  .route("/resetPassword")
  .put(controller.verifyUser, controller.resetPassword); // is used to reset password

export default router;
