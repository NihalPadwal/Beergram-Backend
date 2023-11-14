import UserModel from "../model/User.model.js";
import UserOTPVerification from "../model/UserOTPVerification.model.js";
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
                isAuthenticated: false,
              });

              // return save result as a response
              user
                .save()
                .then(async (result) => {
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

                  // end return statement
                  res.status(201).send({ msg: "User Register Successfully" });
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

/** GET: http://localhost:8080/api/user/example123 */
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

      // fetch user from user model and user authentication detail from userOTPVerification model
      const user = await UserModel.findOne({ _id: userID });

      if (!user)
        return res.status(404).send({ error: "Couldn't find the user" });

      /** remove password from user */
      // mongoose return unnecessary data with object so convert it into json
      const { password, ...rest } = Object.assign({}, user.toJSON());

      // all went good return status 201
      return res.status(201).send(rest);
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
      res.status(201).send({ msg: `OTP is sent` });
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
