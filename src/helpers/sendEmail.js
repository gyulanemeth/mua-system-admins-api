import nodemailer from 'nodemailer'
import aws from '@aws-sdk/client-ses'
import { ValidationError } from 'standard-api-errors'

const accessKeyId = process.env.AWS_ACCESS_KEY_ID
const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY

const mailOptions = {
  from: 'testing@gmail.com',
  to: '',
  subject: '', // Subject line
  html: '' // html body
}

export default async (to, subject, template) => {
  try {
    let transporter
    if (process.env.NODE_ENV === 'test') {
      const testAccount = await nodemailer.createTestAccount()
      transporter = await nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      })
    } else {
      const sesClient = new aws.SESClient({
        region: 'us-east-1',
        credentials: {
          accessKeyId,
          secretAccessKey
        }
      })
      transporter = nodemailer.createTransport({
        SES: { ses: sesClient, aws }
      })
    }
    mailOptions.to = to
    mailOptions.subject = subject
    mailOptions.html = template

    const info = await transporter.sendMail(mailOptions).then(res => res)
    return {
      status: 200,
      result: {
        info
      }
    }
  } catch (err) {
    return new ValidationError('Check your sending to field')
  }
}
