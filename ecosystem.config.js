const process = require('node:process')
const dotenv = require('dotenv')

dotenv.config()

module.exports = {
  apps: [
    {
      name: 'ticketing.dev',
      exec_mode: 'fork',
      instances: '1',
      script: 'app.js',
      port: process.env.PORT,
    },
      {
      name: 'ticketing-staging.dev',
      exec_mode: 'fork',
      instances: '1',
      script: 'app.js',
      port: process.env.PORT,
    },
  ],
}
