import 'dotenv/config';

export const { PORT, DB_URI, JWT_KEY, JWT_TIMEOUT } = process.env;

export const MESSAGES = {
  INTERNAL_SERVER_ERROR: 'Internal Server Error. Please try again!',
  INVALID_CREDENTIALS: 'Invalid Credentials',
  LOGIN_SUCCESS: 'Login Success',
  UNAUTHORIZED: 'Unauthorized access',
  INPUT_VALIDATION_ERROR: 'Input Validation Error',
  INVALID_REQUEST: 'Invalid Request',
  ROUTE_DOES_NOT_EXIST: 'Sorry Route does not exists',
  SERVER_STARTED: `Server running on port ${PORT}`,
  DB_CONNECTED: 'DB Connected',
  INVALID_EMAIL: 'invalid email',
  USER_EXISTS: 'user exists',
  INVALID_RECORD: 'record does not exist',
  UNSPECIFIED_INPUT: 'request contains unspecified input',
  INVALID_PERMISSION: 'this user does not have the requires permissions',
};
