// Third party
import sgMail from '@sendgrid/mail'

// Local
import emailVerificationTemplate from '../templates/emailVerification'

// Configurations
import { FRONTEND_ORIGIN, SENDGRID_API_KEY } from '../config'

const sendVerificationEmail = async (email, token): Promise<void> => {
  const link = `${FRONTEND_ORIGIN}/auth/verify-email?token=${token}`
  const html = emailVerificationTemplate({
    callToActionlink: link,
    bannerImageURL:
      'https://distnode-static-prod.s3.amazonaws.com/distnode-twitter-header.jpg',
    headerText: 'Welcome to DistNode',
    bodyText: 'Please verify your email address to complete your registration.',
    callToActionLink: link,
    callToActionButtonText: 'Verify Email'
  })

  sgMail.setApiKey(SENDGRID_API_KEY)

  const msg = {
    to: email,
    from: 'registration@distnode.com',
    subject: 'Distnode Email Verification',
    text: `Please verify your email by visting the following link: ${link}`,
    html
  }

  sgMail
    .send(msg)
    .then(() => {
      console.log('Email verification sent to:', email)
    })
    .catch((error) => {
      console.error(error.toString())
    })
}

export default sendVerificationEmail
