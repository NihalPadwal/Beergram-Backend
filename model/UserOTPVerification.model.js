import mongoose from "mongoose";

export const UserOTPVerificationSchema = new mongoose.Schema({
  userID: { type: String, required: [true, "Please provide unique UserId"] },
  otp: { type: String },
  resetSession: {
    type: Boolean,
    required: [true, "Please provide a ResetSession"],
  },
});

export default mongoose.model.UserOTPVerification ||
  mongoose.model("UserOTPVerification", UserOTPVerificationSchema);
