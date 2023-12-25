import mongoose from "mongoose";

export const PostSchema = new mongoose.Schema({
  userID: { type: String, required: [true, "Please provide unique UserId"] },
  isImage: { type: Boolean, required: [true, "isImage is required"] },
  isVideo: { type: Boolean, required: [true, "isVideo is required"] },
  contentUrl: { type: String, required: [true, "content url is required"] },
  likeCount: { type: Number, required: [true, "like count is required"] },
  commentCount: { type: Number, required: [true, "comment count is required"] },
});

export default mongoose.model.Post || mongoose.model("Post", PostSchema);
