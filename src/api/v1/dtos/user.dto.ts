import { body, param } from 'express-validator';

export default {
  create: [
    body('fullname').exists(),
    body('roles').exists().isArray().withMessage('has to be a valid array'),
    body('username').exists(),
    body('password').exists().isStrongPassword().withMessage('has to be a strong alpha-numeric-symbol passwword'),
    body('passwordConfirmation')
      .exists()
      .custom((value: string, { req }) => {
        if (value !== req.body.password) {
          // throw error if passwords do not match
          return false;
        }
        return value;
      }),
  ],
  id: [param('userId').exists()],
  login: [body('username').exists(), body('password').exists()],
};
