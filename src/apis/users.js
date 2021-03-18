import { join } from 'path'
import { User } from '../models'
import { Router } from 'express'
import { randomBytes } from 'crypto'
import { DOMAIN } from '../constants'
import sendMail from '../functions/email-sender'
import Validator from '../middlewares/validator-middleware'
import { userAuth } from '../middlewares/auth-guard'
import { AuthenticateValidations, RegisterValidations, ResetPasswordValidation } from '../validators'

const router = Router()

/**
 * @description To create a new User Account
 * @api /users/api/register
 * @access Public
 * @type POST
 */
router.post("/api/register", RegisterValidations, Validator, async (req, res) => {
	try {
		let { username, email } = req.body;
		// Check if username is already taken
		let user = await User.findOne({ username });
		if (user) {
			return res.status(400).json({ success: false, message: "Username is already taken.", });
		}
		// Check if email is already registered
		user = await User.findOne({ email });
		if (user) {
			return res.status(400).json({ success: false, message: "Email is already registered.", });
		}
		user = new User({
			...req.body,
			verificationCode: randomBytes(20).toString("hex"),
		});
		await user.save();
		// Send the email to the user with a verification link
		let html = `
        <div>
            <h1>Hello, ${user.username}</h1>
            <p>Please click the following link to verify your account</p>
            <a href="${DOMAIN}users/verify-now/${user.verificationCode}">Verify Now</a>
        </div>
    `;
		await sendMail(user.email, "Verify Account", "Please verify Your Account.", html);
		return res.status(201).json({
			success: true,
			message: "Hurray! your account is created please verify your email address.",
		});
	} catch (err) {
		return res.status(500).json({ success: false, message: "An error occurred.", });
	}
});

/**
 * @description To verify a new user's account via email
 * @api /users/verify-now/:verificationCode
 * @access Public <Only vie email
 * @type GET
 */
router.get("/verify-now/:verificationCode", async (req, res) => {
	try {
		let { verificationCode } = req.params
		let user = await User.findOne({ verificationCode })
		if (!user) {
			return res.status(401).json({ success: false, message: "Unauthorized access. Invalid verification code" })
		}
		user.verified = true
		user.verificationCode = undefined
		await user.save()
		return res.sendFile(join(__dirname, "../templates/verification-success.html"))
	} catch (err) {
		console.log("ERR", err.message);
		return res.sendFile(join(__dirname, "../templates/errors.html"))
	}
})

/**
 * @description To authenticate a user and get auth token
 * @api /users/api/authenticate
 * @access Public <Only vie email>
 * @type POST
 */
router.post("/api/authenticate", AuthenticateValidations, Validator, async (req, res) => {
	try {
		let { username, password } = req.body;
		let user = await User.findOne({ username });
		if (!user) {
			return res.status(404).json({ success: false, message: "Username not found.", });
		}
		if (!(await user.comparePassword(password))) {
			return res.status(401).json({ success: false, message: "Incorrect password.", });
		}
		let token = await user.generateJWT();
		return res.status(200).json({
			success: true,
			user: user.getUserInfo(),
			token: `Bearer ${token}`,
			message: "Hurray! You are now logged in.",
		});
	} catch (err) {
		return res.status(500).json({ success: false, message: "An error occurred.", });
	}
});

/**
 * @description To get the authenticated user's profile
 * @api /users/api/authenticate
 * @access Private
 * @type GET
 */
router.get("/api/authenticate", userAuth, async (req, res) => {
	return res.status(200).json({ user: req.user })
})

/**
 * @description To initiate the password reset method
 * @api /users/reset-password/
 * @access Public
 * @type POST
 */
router.put('/api/reset-password', ResetPasswordValidation, Validator, async (req, res) => {
	try {
		let { email } = req.body
		let user = await User.findOne({ email })
		if (!user) {
			return res.status(404).json({ success: false, message: "User with this email is not found." })
		}
		user.generatePasswordReset()
		await user.save()
		// Send the password email link in the email
		let html = `
        <div>
            <h1>Hello, ${user.username}</h1>
            <p>Please click the following link to reset your password</p>
            <p>If this password reset request is not created by you then you can ignore this email.</p>
            <a href="${DOMAIN}users/reset-password-now/${user.resetPasswordToken}">Reset Password Now</a>
        </div>
    `;
		await sendMail(user.email, "Reset Password", "Please reset your password.", html);
		return res.status(200).json({ success: true, message: "Password reset link is sent to your email." })
	} catch (err) {
		return res.status(500).json({ success: false, message: "An error occurred." })
	}
})

/**
 * @description To render reset password page
 * @api /users/reset-password-now/:resetPasswordToken
 * @access Restricted via email
 * @type GET
 */
router.get('/reset-password-now/:resetPasswordToken', async (req, res) => {
	try {
		let { resetPasswordToken } = req.params
		let user = await User.findOne({ resetPasswordToken, resetPasswordExpiresIn: { $gt: Date.now() } })
		if (!user) {
			return res.status(401).json({ success: false, message: "Password reset token is invalid or has expired." })
		}
		return res.sendFile(join(__dirname, "../templates/password-reset.html"))
	} catch (err) {
		return res.sendFile(join(__dirname, "../templates/errors.html"))
	}
})

/**
 * @description To reset the user's password
 * @api /users/api/reset-password-now
 * @access Restricted via email
 * @type POST
 */
router.post('/api/reset-password-now', async (req, res) => {
	try {
		let { resetPasswordToken, password } = req.body
		let user = await User.findOne({ resetPasswordToken, resetPasswordExpiresIn: { $gt: Date.now() } })
		if (!user) {
			return res.status(401).json({ success: false, message: "Password reset token is invalid or has expired." })
		}
		user.password = password
		user.resetPasswordToken = undefined
		user.resetPasswordExpiresIn = undefined
		user.save()
		// Send notification email that the password has been successfully reset
		let html = `
        <div>
            <h1>Hello, ${user.username}</h1>
            <p>Your password has been reset successfully.</p>
            <p>If this was not done by you please contact me asap on mike.katholnig79@gmail.com.</p>
        </div>
    `;
		await sendMail(user.email, "Password Reset Successful", "You password has changed", html)
		return res.status(200).json({ success: true, message: "Your password is reset successfully." })
	} catch (err) {
		return res.status(500).json({ success: false, message: "Something went wrong." })
	}
})

export default router