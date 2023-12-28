import mongoose from "mongoose";

export const CommentSchema = new mongoose.Schema({
  postId: { type: String, required: [true, "Please provide unique UserId"] },
  comment: { type: String, required: [true, "Please provide comment"] },
  likes: { type: Number, default: 0 },
  repliedToID: { type: String },
  likedBy: { type: [String] },
});

export default mongoose.model.Comment ||
  mongoose.model("Comment", CommentSchema);
