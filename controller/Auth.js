const { User } = require('../model/User');
const crypto = require('crypto');
const { sanitizeUser, sendMail } = require('../services/common');
const jwt = require('jsonwebtoken');

// exports.createUser = async (req, res) => {
//   try {
//     const salt = crypto.randomBytes(16);
//     crypto.pbkdf2(
//       req.body.password,
//       salt,
//       310000,
//       32,
//       'sha256',
//       async function (err, hashedPassword) {
//         const user = new User({ ...req.body, password: hashedPassword, salt });
//         const doc = await user.save();

//         req.login(sanitizeUser(doc), (err) => {
//           // this also calls serializer and adds to session
//           if (err) {
//             res.status(400).json(err);
//           } else {
//             const token = jwt.sign(
//               sanitizeUser(doc),
//               process.env.JWT_SECRET_KEY
//             );
//             res
//               .cookie('jwt', token, {
//                 expires: new Date(Date.now() + 3600000),
//                 httpOnly: true,
//               })
//               .status(201)
//               .json({ id: doc.id, role: doc.role });
//           }
//         });
//       }
//     );
//   } catch (err) {
//     res.status(400).json(err);
//   }
// };

// exports.loginUser = async (req, res) => {
//   const user = req.user;
//   res
//     .cookie('jwt', user.token, {
//       expires: new Date(Date.now() + 3600000),
//       httpOnly: true,
//     })
//     .status(201)
//     .json({ id: user.id, role: user.role });
// };


// Function to create a new user
exports.createUser = async (req, res) => {
  try {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      'sha256',
      async function (err, hashedPassword) {
        if (err) {
          return res.status(500).json({ message: 'Error hashing password' });
        }
        
        // Create a new user with the hashed password and salt
        const user = new User({ ...req.body, password: hashedPassword, salt });
        const doc = await user.save();

        // Sanitize the user data to avoid sending sensitive info
        const sanitizedUser = sanitizeUser(doc);

        // Generate a JWT token for the created user
        const token = jwt.sign(sanitizedUser, process.env.JWT_SECRET_KEY, {
          expiresIn: '1h',
        });

        // Set the token as a cookie and include it in the response body
        res
          .cookie('jwt', token, {
            expires: new Date(Date.now() + 3600000), // 1 hour expiry
            httpOnly: true,
          })
          .status(201)
          .json({ id: doc.id, role: doc.role, token });
      }
    );
  } catch (err) {
    res.status(400).json({ error: 'User creation failed', details: err });
  }
};

// Function to log in an existing user
exports.loginUser = async (req, res) => {
  try {
    const user = req.user;

    // Sanitize the user data to avoid sending sensitive info
    const sanitizedUser = sanitizeUser(user);

    // Generate a new JWT token for the user upon login
    const token = jwt.sign(sanitizedUser, process.env.JWT_SECRET_KEY, {
      expiresIn: '1h',
    });

    // Set the token as a cookie and include it in the response body
    res
      .cookie('jwt', token, {
        expires: new Date(Date.now() + 3600000), // 1 hour expiry
        httpOnly: true,
      })
      .status(200)
      .json({ id: user.id, role: user.role, token });
  } catch (err) {
    res.status(400).json({ error: 'Login failed', details: err });
  }
};

exports.logout = async (req, res) => {
  res
    .cookie('jwt', null, {
      expires: new Date(Date.now()),
      httpOnly: true,
    })
    .sendStatus(200)
};

exports.checkAuth = async (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.sendStatus(401);
  }
};

exports.resetPasswordRequest = async (req, res) => {
  const email = req.body.email;
  const user = await User.findOne({ email: email });
  if (user) {
    const token = crypto.randomBytes(48).toString('hex');
    user.resetPasswordToken = token;
    await user.save();

    // Also set token in email
    const resetPageLink =
      'http://localhost:3000/reset-password?token=' + token + '&email=' + email;
    const subject = 'reset password for e-commerce';
    const html = `<p>Click <a href='${resetPageLink}'>here</a> to Reset Password</p>`;

    // lets send email and a token in the mail body so we can verify that user has clicked right link

    if (email) {
      const response = await sendMail({ to: email, subject, html });
      res.json(response);
    } else {
      res.sendStatus(400);
    }
  } else {
    res.sendStatus(400);
  }
};

exports.resetPassword = async (req, res) => {
  const { email, password, token } = req.body;

  const user = await User.findOne({ email: email, resetPasswordToken: token });
  if (user) {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      'sha256',
      async function (err, hashedPassword) {
        user.password = hashedPassword;
        user.salt = salt;
        await user.save();
        const subject = 'password successfully reset for e-commerce';
        const html = `<p>Successfully able to Reset Password</p>`;
        if (email) {
          const response = await sendMail({ to: email, subject, html });
          res.json(response);
        } else {
          res.sendStatus(400);
        }
      }
    );
  } else {
    res.sendStatus(400);
  }
};
