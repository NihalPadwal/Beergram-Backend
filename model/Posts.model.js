import mongoose from "mongoose";

export const PostSchema = new mongoose.Schema(
  {
    userID: {
      type: String,
      required: [true, "Please provide unique UserId"],
      ref: "User",
    },
    isImage: { type: Boolean, required: [true, "isImage is required"] },
    isVideo: { type: Boolean, required: [true, "isVideo is required"] },
    contentUrl: { type: String, required: [true, "content url is required"] },
    caption: { type: String },
    likeCount: { type: Number, required: [true, "like count is required"] },
    likedBy: { type: [String], ref: "User" },
    commentCount: {
      type: Number,
      required: [true, "comment count is required"],
    },
  },
  { timestamps: true }
);

export default mongoose.model.Post || mongoose.model("Post", PostSchema);
