// Third party
import sgMail from '@sendgrid/mail'

// Local
import callToActionEmail from '../templates/callToActionEmail'

// Configurations
import { FRONTEND_ORIGIN, SENDGRID_API_KEY } from '../config'

const sendPasswordResetEmail = async (email, token): Promise<void> => {
  const link = `${FRONTEND_ORIGIN}/auth/password-reset?token=${token}`
  const html = callToActionEmail({
    callToActionlink: link,
    bannerImageURL:
      'https://distnode-static-prod.s3.amazonaws.com/distnode-twitter-header.jpg',
    headerText: 'Password Reset for DistNode',
    bodyText:
      'A password reset request has been submitted for your DistNode account.' +
      ' If you did not request a password reset, please ignore this email.',
    callToActionLink: link,
    callToActionButtonText: 'Reset Password'
  })

  sgMail.setApiKey(SENDGRID_API_KEY)

  const msg = {
    to: email,
    from: 'accounts@distnode.com',
    subject: 'DistNode Password Reset',
    text:
      `Please verify your email by visting the following link: ${link}` +
      ' If you did not request a password reset, please ignore this email.',
    html
  }

  sgMail
    .send(msg)
    .then(() => {
      console.log('Password reset email sent to:', email)
    })
    .catch((error) => {
      console.error(error.toString())
    })
}

export default sendPasswordResetEmail
