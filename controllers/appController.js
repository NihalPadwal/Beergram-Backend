// Models
import UserModel from "../model/User.model.js";
import UserOTPVerification from "../model/UserOTPVerification.model.js";
import PostModel from "../model/Posts.model.js";
import CommentsModel from "../model/Comments.model.js";

// Plugins
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import otpGenerator from "otp-generator";
import * as dotenv from "dotenv";
dotenv.config();

// middleware for verify user
export async function verifyUser(req, res, next) {
  try {
    const { username } = req.method == "GET" ? req.query : req.body;

    // check the user existance
    let exist = await UserModel.findOne({ username });
    if (!exist) return res.status(404).send({ error: "Can't find User" });
    next();
  } catch (error) {
    return res.status(404).send({ error: "Authentication Error" });
  }
}

/** POST: http://localhost:8080/api/register 
 * @param : {
  "username" : "example123",
  "password" : "admin123",
  "email": "example@gmail.com",
  "firstName" : "bill",
  "lastName": "william",
  "mobile": 8009860560,
  "address" : "Apt. 556, Kulas Light, Gwenborough",
  "profile": ""
  "followerCount": 0,
  "followingCount": 0,
  "postsCount": 0,
  "info": "desc",
}
*/
export async function register(req, res) {
  try {
    const { username, password, profile, email } = req.body;

    // check the existing user
    const existUsername = new Promise((resolve, reject) => {
      UserModel.findOne({ username }, function (err, user) {
        if (err) reject(new Error(err));
        if (user) reject({ error: "Please use unique username" });

        resolve();
      });
    });

    // check for existing email
    const existEmail = new Promise((resolve, reject) => {
      UserModel.findOne({ email }, function (err, email) {
        if (err) reject(new Error(err));
        if (email) reject({ error: "Please use unique Email" });

        resolve();
      });
    });

    Promise.all([existUsername, existEmail])
      .then(() => {
        if (password) {
          bcrypt
            .hash(password, 10)
            .then((hashedPassword) => {
              const user = new UserModel({
                username,
                password: hashedPassword,
                profile: profile || "",
                email,
                mobile: "",
                isAuthenticated: false,
                address: "",
                followerCount: 0,
                followingCount: 0,
                postsCount: 0,
                info: "",
              });

              // return save result as a response
              user
                .save()
                .then(async (result) => {
                  // console.log(result);
                  const user = await UserModel.findOne({ username });

                  // mongoose return id of user
                  const { _id } = Object.assign({}, user.toJSON());

                  // create new entrty for
                  const userVerification = new UserOTPVerification({
                    userID: _id,
                    otp: "",
                    resetSession: false,
                  });

                  // save previously created entry
                  await userVerification
                    .save()
                    .catch((err) => res.status(500).send({ err }));

                  // crate jwt token ( json web token )
                  const token = jwt.sign(
                    {
                      userId: _id,
                      username: username,
                    },
                    process.env.JWT_SECRET,
                    { expiresIn: "24h" }
                  );

                  // end return statement
                  res
                    .status(201)
                    .send({ msg: "User Register Successfully", token: token });
                })
                .catch((error) => res.status(500).send({ error }));
            })
            .catch((error) => {
              return res.status(500).send({
                error: "Enable to hashed password",
              });
            });
        }
      })
      .catch((error) => {
        return res.status(500).send({ error });
      });
  } catch (error) {
    return res.status(500).send(error);
  }
}

/** POST: http://localhost:8080/api/login 
 * @param: {
  "username" : "example123",
  "password" : "admin123"
}
*/
export async function login(req, res) {
  const { username, password } = req.body;
  try {
    UserModel.findOne({ username })
      .then((user) => {
        bcrypt
          .compare(password, user.password)
          .then((passwordCheck) => {
            if (!passwordCheck)
              return res.status(400).send({ error: "Don't have password" });

            // crate jwt token ( json web token )
            const token = jwt.sign(
              {
                userId: user._id,
                username: user.username,
              },
              process.env.JWT_SECRET,
              { expiresIn: "24h" }
            );

            return res.status(200).send({
              msg: "Login Successsful...!",
              username: user.username,
              token,
            });
          })
          .catch((error) => {
            return res.status(400).send({ error: "Password does not exists" });
          });
      })
      .catch((error) => {
        return res.status(404).send({ error: "Username not Found" });
      });
  } catch (error) {
    return res.status(500).send({ error });
  }
}

/** GET: http://localhost:8080/api/user 
 * @param : {
  "Authentication" : "Bearer ${token}",
}
*/
export async function getUser(req, res) {
  try {
    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const username = decoded.username;
      const usernameByPara = req.query.username;
      const isLoggedUser = username === usernameByPara;
      const selectedUser = req.query.selectedUserId || "";

      // fetch user from user model and user authentication detail from userOTPVerification model
      const user = await UserModel.findOne(
        usernameByPara ? { username: usernameByPara } : { _id: userID }
      ).select("-followingList -followerList -mobile -address");

      if (!user)
        return res.status(404).send({ error: "Couldn't find the user" });

      /** remove password from user */
      // mongoose return unnecessary data with object so convert it into json
      const { password, ...rest } = Object.assign({}, user.toJSON());

      // if already follower value
      // const isAlreadyFollower = user.followingList.some(
      //   (obj) => obj === selectedUser
      // );
      // console.log(user, user.followingList, selectedUser, isAlreadyFollower);

      // all went good return status 201
      return res.status(201).send({
        ...rest,
        isLoggedUser: isLoggedUser,
        // isAlreadyFollower: isAlreadyFollower,
      });
    });
  } catch (error) {
    return res.status(404).send({ error });
  }
}

/** PUT: http://localhost:8080/api/updateuser 
 * @param: {
  "header" : "<token>"
}
body: {
    firstName: '',
    address : '',
    profile : ''
}
*/
export async function updateUser(req, res) {
  try {
    // const id = req.query.id;
    // const { userId } = req.user;

    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const username = decoded.username;

      if (userID) {
        const body = req.body;

        // update the data
        UserModel.updateOne({ _id: userID }, body, function (err, data) {
          if (err) throw err;
          return res.status(201).send({ msg: "Record updated...!" });
        });
      } else {
        return res.status(401).send({ error: "User not found...!" });
      }
    });
  } catch (error) {
    return res.status(401).send({ error: error });
  }
}

/** GET: http://localhost:8080/api/generateOTP
* @param: {
  "username" : example123,
  "userID" : "654f1e31e6da5765757c9181"
} */
export async function generateOTP(req, res) {
  try {
    // take user Id from query
    // const { userID } = req.query;

    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const username = decoded.username;

      // fetch user from user model and user authentication detail from userOTPVerification model
      const user = await UserModel.findOne({ _id: userID });
      const userAuthentication = await UserOTPVerification.findOne({ userID });

      // if user and userAuthentication is undefined that means user does not exists!
      if (!user || !userAuthentication)
        return res.status(404).send({ error: "User Not Found!" });

      // create otp
      const otp = await otpGenerator.generate(6, {
        lowerCaseAlphabets: false,
        upperCaseAlphabets: false,
        specialChars: false,
      });

      // update entriy with same useID
      UserOTPVerification.updateOne(
        { userID },
        {
          otp: otp,
          resetSession: false,
        },
        function (err, data) {
          if (err) throw err;
        }
      );

      // all went good return status 201
      res.status(201).send({ msg: `OTP is sent`, code: otp });
    });
  } catch (error) {
    return res.status(500).send(error);
  }
}

/** GET: http://localhost:8080/api/verifyOTP */
export async function verifyOTP(req, res) {
  try {
    const { code } = req.query;

    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const username = decoded.username;

      const isUser = await UserModel.findOne({ _id: userID });
      const userAuthentication = await UserOTPVerification.findOne({ userID });

      if (!isUser) {
        return res.status(404).send({ error: "No User Found" });
      }

      if (userAuthentication.otp === code) {
        // update the data in userOTPVerification otp to empty string and resetSession to true
        // resetSession true means now user can reset password
        UserOTPVerification.updateOne(
          { userID },
          { otp: "", resetSession: true },
          function (err, data) {
            if (err) throw err;
          }
        );

        // update the data in UserModel set isAuthenticated to true
        // if isAuthenticated is true that means user has successfully verified otp method
        if (!isUser.isAuthenticated) {
          UserModel.updateOne(
            { _id: userID },
            { isAuthenticated: true },
            function (err, data) {
              if (err) throw err;
            }
          );
        }

        return res.status(201).send({ msg: "Verify Successsfully!" });
      }

      return res.status(400).send({ error: "Invalid OTP" });
    });
  } catch (err) {
    return res.status(500).send({ error: "Something went wrong!" });
  }
}

// successfully redirect user when OTP is valid
/** GET: http://localhost:8080/api/createResetSession */
export async function createResetSession(req, res) {
  if (req.app.locals.resetSession) {
    req.app.locals.resetSession = false;
    return res.status(201).send({ msg: "access granted!" });
  }
  return res.status(440).send({ error: "Session expired!" });
}

// update the password when we have valid session
/** PUT: http://localhost:8080/api/resetPassword */
export async function resetPassword(req, res) {
  try {
    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const username = decoded.username;

      const { password } = req.body;

      const userAuthentication = await UserOTPVerification.findOne({ userID });

      if (!userAuthentication.resetSession)
        return res.status(440).send({ error: "Session expired!" });

      try {
        UserModel.findOne({ _id: userID })
          .then((user) => {
            bcrypt
              .hash(password, 10)
              .then((hashedPassword) => {
                UserModel.updateOne(
                  { username: username },
                  { password: hashedPassword },
                  async function (err, data) {
                    if (err) throw err;
                    // req.app.locals.resetSession = false;
                    const userAuthentication =
                      await UserOTPVerification.findOne({ userID });
                    // update the data in userOTPVerification resetSession to true
                    // resetSession true means now user can reset password
                    UserOTPVerification.updateOne(
                      { userID },
                      { resetSession: false },
                      function (err, data) {
                        if (err) throw err;
                      }
                    );
                    return res
                      .status(201)
                      .send({ error: "Record Updated...!" });
                  }
                );
              })
              .catch((error) => {
                return res
                  .status(500)
                  .send({ error: "Unable to hashed password" });
              });
          })
          .catch((error) => {
            return res.status(404).send({ error: "Username not Found!" });
          });
      } catch (error) {
        return res.status(500).send({ error });
      }
    });
  } catch (error) {
    return res.status(401).send({ error });
  }
}

// FOR POSTS

/** POST: http://localhost:8080/api/createPost 
 * @param : {
  "username": "Nihal",
  "userID" : "asd234DG@hdh1D(asd",
  "isImage" : "true",
  "isVideo": "false",
  "contentUrl" : "www.content.com",
  "likeCount": "0",
  "commentCount": 0,
}
*/
export async function createPost(req, res) {
  try {
    const {
      userID,
      isImage,
      isVideo,
      contentUrl,
      likeCount,
      commentCount,
      caption,
    } = req.body;

    const post = new PostModel({
      userID,
      isImage: isImage || false,
      isVideo: isVideo || false,
      contentUrl: contentUrl || "",
      likeCount: likeCount || 0,
      commentCount: commentCount || 0,
      caption: caption || "",
    });

    // return save result as a response
    post
      .save()
      .then(async (result) => {
        console.log(result);
        // end return statement
        res
          .status(201)
          .send({ msg: "Post Created Successfully", data: result });
      })
      .catch((error) => res.status(500).send({ error }));
  } catch (error) {
    return res.status(500).send(error);
  }
}

/** GET: http://localhost:8080/api/posts 
 * @param : {
  "Authentication" : "Bearer ${token}",
}
*/
export async function getPosts(req, res) {
  try {
    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const usernameByPara = req.query.username;

      if (usernameByPara) {
        // fetch user from user model and user authentication detail from userOTPVerification model
        const user = await UserModel.findOne({ username: usernameByPara });

        if (!user)
          return res.status(404).send({ error: "Couldn't find the user" });

        /** remove password from user */
        // mongoose return unnecessary data with object so convert it into json
        const { _id } = Object.assign({}, user.toJSON());

        // fetch posts from post model using token
        const posts = await PostModel.find({ userID: _id });

        if (!posts)
          return res.status(404).send({ error: "Couldn't find the user" });

        // all went good return status 201
        return res.status(201).send(posts);
      }

      // fetch posts from post model using token
      const posts = await PostModel.find({ userID: userID });

      if (!posts)
        return res.status(404).send({ error: "Couldn't find the user" });

      // all went good return status 201
      return res.status(201).send(posts);
    });
  } catch (error) {
    return res.status(404).send({ error });
  }
}

/** POST: http://localhost:8080/api/createComment 
 * @param : {
  "username": "Nihal",
  "postId" : "asd234DG@hdh1D(asd",
  "comment" : "First Comment",
  "likes": "10",
  "repliedToID" : "c2as92##asdj",
}
*/
export async function createComment(req, res) {
  try {
    const { postId, comment, likes, repliedToID } = req.body;

    const comments = new CommentsModel({
      postId,
      comment: comment,
      likes: likes,
      repliedToID: repliedToID || "",
    });

    // return save result as a response
    comments
      .save()
      .then(async (result) => {
        // end return statement
        res.status(201).send({ msg: "Comments Created Successfully" });
      })
      .catch((error) => res.status(500).send({ error }));
  } catch (error) {
    return res.status(500).send(error);
  }
}

/** GET: http://localhost:8080/api/comments 
 * @param : {
  "postId": "asd234DG@hdh1D(asd"
}
*/
export async function getComments(req, res) {
  try {
    const { postId } = req.query;

    // fetch posts from post model using token
    const comments = await CommentsModel.find({ postId });

    if (!comments)
      return res.status(404).send({ error: "Couldn't find the comment" });

    return res.status(201).send(comments);
  } catch (error) {
    return res.status(404).send({ error });
  }
}

/** PUT: http://localhost:8080/api/likeComment 
 * @param : {
  "id": "asd234DG@hdh1D(asd",
  "likes": 1,
  "likedById" : "v203asd2'hda"
}
*/
export async function likeComment(req, res) {
  try {
    const { id, likes, likedById } = req.body;

    if (!id || !likes)
      return res.status(404).send({ error: "Id and likes are required" });

    // fetch posts from post model using token
    const comment = await CommentsModel.findOne({ _id: id });

    if (!comment) return res.status(404).send({ error: "Comment Not Found!" });

    const likedByList = comment.likedBy.includes(likedById)
      ? comment.likedBy.filter((item) => item != likedById)
      : [...comment.likedBy, likedById];

    // update entriy with same useID
    CommentsModel.updateOne(
      { _id: id },
      {
        likes,
        likedBy: likedByList,
      },
      function (err, data) {
        if (err) throw err;
      }
    );

    return res.status(201).send("Updated likes on comment");
  } catch (error) {
    return res.status(404).send({ error });
  }
}

/** GET: http://localhost:8080/api/searchUsers 
 * @param : {
  "username" : "Nihal",
  "Authentication" : "Bearer ${token}",
}
*/
export async function searchUsers(req, res) {
  try {
    const { username } = req.query;

    if (!username) {
      return res
        .status(400)
        .send({ error: "Username is required for search." });
    }

    // Search for users with matching usernames, limit to 10, and sort by followers in descending order
    const users = await UserModel.find({
      username: { $regex: username, $options: "i" },
    })
      .limit(10)
      .sort({ followerCount: -1 })
      .select(
        "-password -isAuthenticated -info -isAuthenticated -mobile -address"
      );

    res.status(200).send(users);
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Internal Server Error" });
  }
}

/** PUT: http://localhost:8080/api/followUser 
 * @param : {
  "toUser" : "v203asd2hda"              // follow request to follow user
}
*/
export async function followUser(req, res) {
  try {
    const { toUser } = req.body;

    if (!toUser) return res.status(404).send({ error: "toUser are required" });

    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;

      // fetch users (user who want to follow [fromUserModel], user who gets new follower[toUserModel]) from post model using token
      const fromUserModel = await UserModel.findOne({ _id: userID });
      const toUserModel = await UserModel.findOne({ _id: toUser });

      if (!fromUserModel)
        return res.status(404).send({ error: "from User Model Not Found!" });
      if (!toUserModel)
        return res.status(404).send({ error: "to User Model Not Found!" });

      // change user who wants to follow following list
      const fromUserFollowingList = fromUserModel.followingList.includes(toUser)
        ? fromUserModel.followingList.filter((item) => item != toUser)
        : [...fromUserModel.followingList, toUser];

      // change user who gets a follower follower list
      const toUserFollowerList = toUserModel.followerList.includes(userID)
        ? toUserModel.followerList.filter((item) => item != userID)
        : [...toUserModel.followerList, userID];

      // update fromUserModel entriy with same useID
      UserModel.updateOne(
        { _id: userID },
        {
          followingCount: fromUserFollowingList.length,
          followingList: fromUserFollowingList,
        },
        function (err, data) {
          if (err) throw err;
        }
      );

      // update toUserModel entriy with same useID
      UserModel.updateOne(
        { _id: toUser },
        {
          followerCount: toUserFollowerList.length,
          followerList: toUserFollowerList,
        },
        function (err, data) {
          if (err) throw err;
        }
      );

      return res
        .status(201)
        .send({ message: "Follow request completed successfully" });
    });
  } catch (error) {
    return res.status(404).send({ error });
  }
}

/** GET: http://localhost:8080/api/getIsUserAlreadyFollower 
 * @param : {
  "Authentication" : "Bearer ${token}",
  "selectedUser": "asdcvjwq2e12"
}
*/
export async function getIsUserAlreadyFollower(req, res) {
  try {
    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;
      const selectedUser = req.query.selectedUser;

      // fetch user from user model and user authentication detail from userOTPVerification model
      const user = await UserModel.findOne({
        _id: userID,
      }).select("followingList");

      const followersArray = user.followingList;

      const isFollowed = followersArray.some((obj) => obj === selectedUser);

      if (!user)
        return res.status(404).send({ error: "Couldn't find the user" });

      /** remove password from user */
      // mongoose return unnecessary data with object so convert it into json

      // all went good return status 201
      return res.status(201).send({
        isFollowed,
      });
    });
  } catch (error) {
    return res.status(404).send({ error });
  }
}

/** GET: http://localhost:8080/api/getUserStats 
 * @param : {
  "Authentication" : "Bearer ${token}",
}
*/
export async function getUserStats(req, res) {
  try {
    // if in-correct or no token return status 500
    if (!req.headers.authorization)
      return res.status(500).send({ error: "Please provide correct token" });

    // access authorize header to validate request
    const token = req.headers.authorization.split(" ")[1];

    // decode token into userId and username
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error(err);
        throw err;
      }

      // Token is valid, and 'decoded' contains the payload
      const userID = decoded.userId;

      // fetch user from user model and user authentication detail from userOTPVerification model
      const user = await UserModel.findOne({ _id: userID }).select(
        "followerCount followingCount"
      );

      // fetch posts from post model using token
      const posts = await PostModel.find({ userID: userID });

      if (!user)
        return res.status(404).send({ error: "Couldn't find the user" });

      /** remove password from user */
      // mongoose return unnecessary data with object so convert it into json
      const { password, ...rest } = Object.assign({}, user.toJSON());

      // all went good return status 201
      return res.status(201).send({
        ...rest,
        postLength: posts.length,
      });
    });
  } catch (error) {
    return res.status(404).send({ error });
  }
}
